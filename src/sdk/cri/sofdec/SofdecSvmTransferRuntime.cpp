
  /**
   * Address: 0x00ACCAE0 (FUN_00ACCAE0, _MWSFSVM_EntryVint)
   *
   * What it does:
   * Registers one VINT callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryVint(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(0, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVintSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB20 (FUN_00ACCB20, _MWSFSVM_EntryVfunc)
   *
   * What it does:
   * Registers one VSYNC callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryVfunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(2, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVsyncSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB40 (FUN_00ACCB40, _MWSFSVM_EntryIdVfunc)
   *
   * What it does:
   * Registers one VSYNC callback lane at explicit slot id and updates cached
   * VSYNC slot-id lane.
   */
  std::int32_t MWSFSVM_EntryIdVfunc(
    const std::int32_t laneId,
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    SVM_SetCbSvrIdWithString(2, laneId, callbackAddress, callbackObject, callbackName);
    gMwsfsvmVsyncSlotId = laneId;
    return laneId;
  }

  /**
   * Address: 0x00ACCBD0 (FUN_00ACCBD0, _MWSFSVM_EntryMainFunc)
   *
   * What it does:
   * Registers one MAIN callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryMainFunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(5, callbackAddress, callbackObject, callbackName);
    gMwsfsvmMainSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB90 (FUN_00ACCB90, _MWSFSVM_EntryIdleFunc)
   *
   * What it does:
   * Registers one IDLE callback lane and caches selected slot id.
   */
  std::int32_t MWSFSVM_EntryIdleFunc(
    const std::int32_t callbackAddress,
    const std::int32_t callbackObject,
    const char* const callbackName
  )
  {
    const std::int32_t result = SVM_SetCbSvrWithString(6, callbackAddress, callbackObject, callbackName);
    gMwsfsvmIdleSlotId = result;
    return result;
  }

  /**
   * Address: 0x00ACCB00 (FUN_00ACCB00, _MWSFSVM_DeleteVint)
   *
   * What it does:
   * Deletes cached VINT callback lane from SVM table.
   */
  void MWSFSVM_DeleteVint()
  {
    SVM_DelCbSvrWithLock(0, gMwsfsvmVintSlotId);
  }

  /**
   * Address: 0x00ACCB70 (FUN_00ACCB70, _MWSFSVM_DeleteVfunc)
   *
   * What it does:
   * Deletes cached VSYNC callback lane from SVM table.
   */
  void MWSFSVM_DeleteVfunc()
  {
    SVM_DelCbSvrWithLock(2, gMwsfsvmVsyncSlotId);
  }

  /**
   * Address: 0x00ACCBB0 (FUN_00ACCBB0, _MWSFSVM_DeleteIdleFunc)
   *
   * What it does:
   * Deletes cached IDLE callback lane from SVM table.
   */
  void MWSFSVM_DeleteIdleFunc()
  {
    SVM_DelCbSvrWithLock(6, gMwsfsvmIdleSlotId);
  }

  /**
   * Address: 0x00ACCBF0 (FUN_00ACCBF0, _MWSFSVM_DeleteMainFunc)
   *
   * What it does:
   * Deletes cached MAIN callback lane from SVM table.
   */
  void MWSFSVM_DeleteMainFunc()
  {
    SVM_DelCbSvrWithLock(5, gMwsfsvmMainSlotId);
  }

  /**
   * Address: 0x00B0C760 (FUN_00B0C760, _SVM_SetCbErr)
   *
   * What it does:
   * Publishes one process-global SVM error callback lane under SVM lock.
   */
  void SVM_SetCbErr(moho::AdxmErrorCallback callback, const std::int32_t callbackParam)
  {
    SVM_Lock();
    gSvmErrorCallback.fn = callback;
    gSvmErrorCallback.callbackObject = callbackParam;
    SVM_Unlock();
  }

  /**
   * Address: 0x00B06C00 (FUN_00B06C00, _ADXM_SetCbErr)
   * Body: 0x00B0C760 (_SVM_SetCbErr)
   *
   * What it does:
   * Forwards ADXM error callback registration to SVM callback lane owner.
   */
  void ADXM_SetCbErr(moho::AdxmErrorCallback callback, const std::int32_t callbackParam)
  {
    SVM_SetCbErr(callback, callbackParam);
  }

  /**
   * Address: 0x00ACCD10 (FUN_00ACCD10, _mwPlyEntryErrFn)
   *
   * What it does:
   * Playback thunk that registers one ADXM/SVM error callback pair.
   */
  void mwPlyEntryErrFn(moho::AdxmErrorCallback callback, const std::int32_t callbackParam)
  {
    ADXM_SetCbErr(callback, callbackParam);
  }

  /**
   * Address: 0x00B0B680 (FUN_00B0B680, _adxf_read_sj32)
   *
   * What it does:
   * Configures one ADXF stream window for SJ-backed read and starts ADXSTM
   * sector transfer.
   */
  [[maybe_unused]] std::int32_t adxf_read_sj32(
    AdxfRuntimeHandleView* const adxfHandle,
    const std::int32_t requestedSectors,
    void* const sourceJoinObject
  )
  {
    if (ADXSTM_GetStat(adxfHandle->streamHandle) != 1) {
      ADXSTM_Stop(adxfHandle->streamHandle);
    }

    ADXCRS_Lock();
    const std::int32_t readStartSector = adxfHandle->readStartSector;
    std::int32_t sectorsToRead = adxfHandle->fileSizeSectors - readStartSector;
    adxfHandle->requestSectorStart = adxfHandle->fileStartSector + readStartSector;
    if (requestedSectors < sectorsToRead) {
      sectorsToRead = requestedSectors;
    }
    adxfHandle->requestSectorCount = sectorsToRead;
    adxfHandle->readProgressSectors = 0;
    if (sectorsToRead != 0) {
      ADXSTM_SetEos(adxfHandle->streamHandle, -1);
      ADXSTM_SetSj(adxfHandle->streamHandle, sourceJoinObject);
      ADXSTM_SetReqRdSize(adxfHandle->streamHandle, adxfHandle->requestedReadSizeSectors);
      adxfHandle->status = 2;
      adxfHandle->stopWithoutNetworkFlag = 0;
      ADXSTM_SetPause(adxfHandle->streamHandle, 0);
      ADXSTM_Seek(adxfHandle->streamHandle, adxfHandle->readStartSector);
      ADXSTM_Start2(adxfHandle->streamHandle, adxfHandle->requestSectorCount);

      const std::int32_t startedSectorCount = adxfHandle->requestSectorCount;
      ADXCRS_Unlock();
      return startedSectorCount;
    }

    adxfHandle->status = 3;
    ADXCRS_Unlock();
    return 0;
  }

  /**
   * Address: 0x00B0B170 (FUN_00B0B170, _adxf_CreateAdxFs)
   *
   * What it does:
   * Allocates one ADXF runtime handle and wires a fresh ADX stream owner with
   * default sector-window state.
   */
  [[maybe_unused]] void* adxf_CreateAdxFs()
  {
    auto* const handle = static_cast<AdxfRuntimeHandleView*>(adxf_AllocAdxFs());
    if (handle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfErrCreateNoHandles);
      return nullptr;
    }

    handle->streamHandle = ADXSTM_Create(0, 0x100);
    if (handle->streamHandle == nullptr) {
      (void)ADXERR_CallErrFunc1_(kAdxfErrCreateCannotCreateStream);
      return nullptr;
    }

    handle->status = 1;
    handle->requestSectorStart = 0;
    handle->requestSectorCount = 0;
    handle->readProgressSectors = 0;
    handle->requestedReadSizeSectors = 0x200;
    handle->sjFlag = 0;
    handle->sourceJoinObject = nullptr;
    handle->stopWithoutNetworkFlag = 0;
    handle->used = 1;
    return handle;
  }

  /**
   * Address: 0x00ADDB50 (FUN_00ADDB50, _mwPlyEntryFname)
   */
  void mwPlyEntryFname(moho::MwsfdPlaybackStateSubobj* const ply, const char* const fname)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameInvalidHandle);
      return;
    }
    if (fname == nullptr) {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameNullFileName);
      return;
    }

    if (LSC_EntryFname(ply->lscHandle, fname) >= 0) {
      ++ply->seamlessEntryCount;
      return;
    }

    ply->compoMode = 4;
    (void)MWSFSVM_Error(kMwsfdErrEntryFnameCannotEntryFmt, fname);
  }

  /**
   * Address: 0x00ADDBC0 (FUN_00ADDBC0, _mwPlyStartSeamless)
   */
  void mwPlyStartSeamless(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartSeamlessInvalidHandle);
      return;
    }

    mwPlyLinkStm(ply, 1);
    MWSFD_StartInternalSj(ply, ply->sjRingBufferHandle);
    MWSFPLY_SetFlowLimit(ply);
    lsc_Start(ply->lscHandle);
    if (ply->sjSupplyHandle != nullptr) {
      ply->sjSupplyHandle->dispatchTable->onStart(ply->sjSupplyHandle);
    }
    (void)MWSFCRE_SetSupplySj(ply);
    ply->apiType = 0;
  }

  /**
   * Address: 0x00ADDC30 (FUN_00ADDC30, _mwPlySetSeamlessLp)
   */
  void mwPlySetSeamlessLp(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t enabled)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      LSC_SetLpFlg(ply->lscHandle, enabled);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrSetLpFlagInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDCE0 (FUN_00ADDCE0, _mwPlyReleaseLp)
   */
  void mwPlyReleaseLp(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrReleaseLpInvalidHandle);
      return;
    }

    mwPlySetSeamlessLp(ply, 0);
    mwPlyReleaseSeamless(ply);
  }

  /**
   * Address: 0x00ADDD20 (FUN_00ADDD20, _mwPlyReleaseSeamless)
   */
  void mwPlyReleaseSeamless(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      mwPlyLinkStm(ply, 0);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrReleaseSeamlessInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDD60 (FUN_00ADDD60, _mwPlyEntryAfs)
   */
  void mwPlyEntryAfs(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrEntryAfsInvalidHandle);
      return;
    }

    std::int32_t startOffset = 0;
    std::int32_t rangeStart = 0;
    std::int32_t rangeEnd = 0;
    if (ADXF_GetFnameRangeEx(afsHandle, fileIndex, ply->fname, &startOffset, &rangeStart, &rangeEnd) != 0) {
      (void)MWSFSVM_Error(kMwsfdErrEntryAfsCannotEntryFmt, afsHandle, fileIndex);
      return;
    }

    const char* const afsFileName = ADXF_GetFnameFromPt(afsHandle);
    (void)lsc_EntryFileRange(ply->lscHandle, afsFileName, startOffset, rangeStart, rangeEnd);
  }

  /**
   * Address: 0x00ADDE00 (FUN_00ADDE00, _mwPlyStartAfsLp)
   */
  void mwPlyStartAfsLp(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t afsHandle,
    const std::int32_t fileIndex
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartAfsLpInvalidHandle);
      return;
    }

    lsc_Stop(ply->lscHandle);
    mwPlyEntryAfs(ply, afsHandle, fileIndex);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00ADDE50 (FUN_00ADDE50, _mwPlyEntryFnameRange)
   */
  void mwPlyEntryFnameRange(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (MWSFD_IsEnableHndl(ply) == 1) {
      (void)lsc_EntryFileRange(ply->lscHandle, fname, 0, rangeStart, rangeEnd);
    } else {
      (void)MWSFSVM_Error(kMwsfdErrEntryFnameRangeInvalidHandle);
    }
  }

  /**
   * Address: 0x00ADDEA0 (FUN_00ADDEA0, _mwPlyStartFnameRangeLp)
   */
  void mwPlyStartFnameRangeLp(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const char* const fname,
    const std::int32_t rangeStart,
    const std::int32_t rangeEnd
  )
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrStartFnameRangeLpInvalidHandle);
      return;
    }

    lsc_Stop(ply->lscHandle);
    mwPlyEntryFnameRange(ply, fname, rangeStart, rangeEnd);
    mwPlySetSeamlessLp(ply, 1);
    mwPlyStartSeamless(ply);
  }

  /**
   * Address: 0x00ADDD50 (FUN_00ADDD50, _mwPlyGetNumSlFiles)
   */
  std::int32_t mwPlyGetNumSlFiles(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return LSC_GetNumStm(ply->lscHandle);
  }

  /**
   * Address: 0x00ADDF00 (FUN_00ADDF00, _mwPlyGetSlFname)
   */
  const char* mwPlyGetSlFname(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamIndex)
  {
    if (MWSFD_IsEnableHndl(ply) != 1) {
      (void)MWSFSVM_Error(kMwsfdErrGetSlFnameInvalidHandle);
      return nullptr;
    }

    if (streamIndex < mwPlyGetNumSlFiles(ply)) {
      if (streamIndex >= 0) {
        const std::int32_t streamId = MWSFLSC_GetStmId(ply, streamIndex);
        return MWSFLSC_GetStmFname(ply, streamId);
      }
      (void)MWSFSVM_Error(kMwsfdErrInvalidStreamIndexFmt, streamIndex);
      return nullptr;
    }

    return nullptr;
  }

  /**
   * Address: 0x00ADDF70 (FUN_00ADDF70, _MWSFLSC_GetStat)
   */
  std::int32_t MWSFLSC_GetStat(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return LSC_GetStat(ply->lscHandle);
  }

  /**
   * Address: 0x00ADDF80 (FUN_00ADDF80, _MWSFLSC_GetStmId)
   */
  std::int32_t MWSFLSC_GetStmId(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamIndex)
  {
    return lsc_GetStmId(ply->lscHandle, streamIndex);
  }

  /**
   * Address: 0x00ADDF90 (FUN_00ADDF90, _MWSFLSC_GetStmFname)
   */
  const char* MWSFLSC_GetStmFname(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmFname(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFA0 (FUN_00ADDFA0, _MWSFLSC_GetStmStat)
   */
  std::int32_t MWSFLSC_GetStmStat(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmStat(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFB0 (FUN_00ADDFB0, _MWSFLSC_GetStmRdSct)
   */
  std::int32_t MWSFLSC_GetStmRdSct(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t streamId)
  {
    return lsc_GetStmRdSct(ply->lscHandle, streamId);
  }

  /**
   * Address: 0x00ADDFC0 (FUN_00ADDFC0, _MWSFLSC_IsFsStatErr)
   */
  bool MWSFLSC_IsFsStatErr(void* const lscHandle)
  {
    return LSC_GetStat(lscHandle) == 3;
  }

  /**
   * Address: 0x00ADDFE0 (FUN_00ADDFE0, _MWSFLSC_SetFlowLimit)
   */
  std::int32_t MWSFLSC_SetFlowLimit(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t flowLimit)
  {
    if (ply->lscHandle == nullptr) {
      return 0;
    }
    return lsc_SetFlowLimit(ply->lscHandle, flowLimit);
  }

  /**
   * Address: 0x00ADE0D0 (FUN_00ADE0D0, _MWSFRNA_SetOutVol)
   */
  std::int32_t MWSFRNA_SetOutVol(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t volumeLevel)
  {
    return SFD_SetOutVol(ply->handle, volumeLevel);
  }

  /**
   * Address: 0x00ADE0E0 (FUN_00ADE0E0, _MWSFRNA_GetOutVol)
   */
  std::int32_t MWSFRNA_GetOutVol(moho::MwsfdPlaybackStateSubobj* const ply)
  {
    return SFD_GetOutVol(ply->handle);
  }

  /**
   * Address: 0x00ADE0F0 (FUN_00ADE0F0, _MWSFRNA_SetOutPan)
   */
  std::int32_t MWSFRNA_SetOutPan(
    moho::MwsfdPlaybackStateSubobj* const ply,
    const std::int32_t laneIndex,
    const std::int32_t panLevel
  )
  {
    return SFD_SetOutPan(ply->handle, laneIndex, panLevel);
  }

  /**
   * Address: 0x00ADE100 (FUN_00ADE100, _MWSFRNA_GetOutPan)
   */
  std::int32_t MWSFRNA_GetOutPan(moho::MwsfdPlaybackStateSubobj* const ply, const std::int32_t laneIndex)
  {
    return SFD_GetOutPan(ply->handle, laneIndex);
  }

  /**
   * Address: 0x00ADE400 (FUN_00ADE400, _CFT_Init)
   */
  void CFT_Init()
  {
    gCriVerstrPtrCft = kCriCftVersionString;
    CFT_Ycc420plnToArgb8888Init();
    CFT_Ycc420plnToArgb8888IntInit();
    CFT_Ycc420plnToArgb8888PrgInit();
    CFT_Ycc420plnToRgb565Init();
    CFT_Ycc420plnToRgb555Init();
  }

  namespace
  {
    [[nodiscard]] inline std::int16_t TruncateToI16(const double value) noexcept
    {
      return static_cast<std::int16_t>(static_cast<std::int32_t>(value));
    }

    [[nodiscard]] inline std::int32_t TruncateToI32(const double value) noexcept
    {
      return static_cast<std::int32_t>(value);
    }

    [[nodiscard]] inline double ClampToByteRange(const double value) noexcept
    {
      if (value < 0.0) {
        return 0.0;
      }
      if (value > 255.0) {
        return 255.0;
      }
      return value;
    }

    void BuildArgb8888AlphaChromaTables(std::int16_t* const tableWords)
    {
      for (std::int32_t lane = -128; lane < 128; ++lane) {
        const std::size_t laneIndex = static_cast<std::size_t>(lane + 128);

        std::int16_t* const table0 = tableWords + 1024u + (laneIndex * 4u);
        std::int16_t* const table1 = tableWords + 2048u + (laneIndex * 4u);
        const double laneValue = static_cast<double>(lane);

        table0[0] = TruncateToI16((129.088 * laneValue) + 0.5);
        table0[1] = TruncateToI16(0.5 - (25.088 * laneValue));
        table0[2] = 0;
        table0[3] = 0;

        table1[0] = 0;
        table1[1] = TruncateToI16(0.5 - (52.032 * laneValue));
        table1[2] = TruncateToI16((102.144 * laneValue) + 0.5);
        table1[3] = 0;
      }
    }
  } // namespace

  /**
   * Address: 0x00AEDB70 (FUN_00AEDB70, _CFT_MakeArgb8888Alp3110Tbl)
   *
   * What it does:
   * Builds one ARGB8888 alpha ramp table for 3110 mode:
   * base lane bands in [0x000..0x7FF] and paired chroma lookup lanes in
   * [0x800..0x17FF].
   */
  std::int32_t CFT_MakeArgb8888Alp3110Tbl(
    const std::int32_t tableAddress,
    const std::int32_t alpha0,
    const std::int32_t alpha1,
    const std::int32_t alpha2
  )
  {
    auto* const tableWords = reinterpret_cast<std::int16_t*>(SjAddressToPointer(tableAddress));
    if (tableWords == nullptr) {
      return 0;
    }

    BuildArgb8888AlphaChromaTables(tableWords);

    const std::int16_t alphaLane0 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha0));
    const std::int16_t alphaLane1 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha1) << 6);
    const std::int16_t alphaLane2 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha2) << 6);

    for (std::int32_t index = 0; index < 9; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      entry[0] = 0;
      entry[1] = 0;
      entry[2] = 0;
      entry[3] = alphaLane0;
    }

    std::int32_t result = 0;
    for (std::int32_t index = 9; index < 134; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      const double clamped = ClampToByteRange(static_cast<double>(index) - 16.0);
      result = TruncateToI32((clamped * 148.3636363636364) + 0.5);
      const std::int16_t packed = static_cast<std::int16_t>(result);
      entry[0] = packed;
      entry[1] = packed;
      entry[2] = packed;
      entry[3] = alphaLane1;
    }

    for (std::int32_t index = 134; index < 256; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      const double clamped = ClampToByteRange(251.0 - static_cast<double>(index));
      result = TruncateToI32((clamped * 148.3636363636364) + 0.5);
      const std::int16_t packed = static_cast<std::int16_t>(result);
      entry[0] = packed;
      entry[1] = packed;
      entry[2] = packed;
      entry[3] = alphaLane2;
    }

    return result;
  }

  /**
   * Address: 0x00AEDD50 (FUN_00AEDD50, _CFT_MakeArgb8888Alp3211Tbl)
   *
   * What it does:
   * Builds one ARGB8888 alpha ramp table for 3211 mode:
   * base lane bands in [0x000..0x7FF] and paired chroma lookup lanes in
   * [0x800..0x17FF].
   */
  std::int32_t CFT_MakeArgb8888Alp3211Tbl(
    const std::int32_t tableAddress,
    const std::int32_t alpha0,
    const std::int32_t alpha1,
    const std::int32_t alpha2
  )
  {
    auto* const tableWords = reinterpret_cast<std::int16_t*>(SjAddressToPointer(tableAddress));
    if (tableWords == nullptr) {
      return 0;
    }

    BuildArgb8888AlphaChromaTables(tableWords);

    const std::int16_t alphaLane0 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha0));
    const std::int16_t alphaLane1 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha1) << 6);
    const std::int16_t alphaLane2 = static_cast<std::int16_t>(static_cast<std::uint8_t>(alpha2) << 6);

    for (std::int32_t index = 0; index < 48; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      entry[0] = -1160;
      entry[1] = -1160;
      entry[2] = -1160;
      entry[3] = alphaLane0;
    }

    std::int32_t result = 0;
    for (std::int32_t index = 48; index < 130; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      const double clamped = ClampToByteRange(static_cast<double>(index) - 68.0);
      result = TruncateToI32((clamped * 296.7272727272727) + 0.5);
      const std::int16_t packed = static_cast<std::int16_t>(result);
      entry[0] = packed;
      entry[1] = packed;
      entry[2] = packed;
      entry[3] = alphaLane1;
    }

    for (std::int32_t index = 130; index < 256; ++index) {
      std::int16_t* const entry = tableWords + (static_cast<std::size_t>(index) * 4u);
      const double clamped = ClampToByteRange(247.0 - static_cast<double>(index));
      result = TruncateToI32((clamped * 147.027027027027) + 0.5);
      const std::int16_t packed = static_cast<std::int16_t>(result);
      entry[0] = packed;
      entry[1] = packed;
      entry[2] = packed;
      entry[3] = alphaLane2;
    }

    return result;
  }

  /**
   * Address: 0x00B10490 (FUN_00B10490, _CRICFG_Init)
   *
   * What it does:
   * Clears the CRI config storage lane, publishes CFG version text, and
   * computes aligned entry capacity in 16-byte entry units.
   */
  std::int32_t CRICFG_Init()
  {
    std::memset(gCriConfigEntryStorage.data(), 0, gCriConfigEntryStorage.size());
    gCriVerstrPtrCfg = kCriCfgVersionString;

    const std::uintptr_t storageAddress = reinterpret_cast<std::uintptr_t>(gCriConfigEntryStorage.data());
    const std::uintptr_t alignedAddress = (storageAddress + 3u) & ~std::uintptr_t{3u};

    gCriConfigEntries = reinterpret_cast<CriConfigEntry*>(alignedAddress);
    const std::ptrdiff_t bytesAvailable =
      static_cast<std::ptrdiff_t>(gCriConfigEntryStorage.size()) -
      static_cast<std::ptrdiff_t>(alignedAddress - storageAddress);

    const auto entryCount = static_cast<std::int32_t>(bytesAvailable / static_cast<std::ptrdiff_t>(sizeof(CriConfigEntry)));
    gCriConfigEntryCount = entryCount;
    return entryCount;
  }

  /**
   * Address: 0x00B104D0 (FUN_00B104D0, _CRICFG_Finish)
   *
   * What it does:
   * Clears active CRI config table pointer/count lanes.
   */
  std::int32_t CRICFG_Finish()
  {
    gCriConfigEntries = nullptr;
    gCriConfigEntryCount = 0;
    return 0;
  }

  /**
   * Address: 0x00B10520 (FUN_00B10520, _searchCfgInfoFree)
   *
   * What it does:
   * Finds the first free CRI config entry (key byte `0`) in the active table.
   */
  CriConfigEntry* searchCfgInfoFree()
  {
    if (gCriConfigEntries == nullptr || gCriConfigEntryCount <= 0) {
      return nullptr;
    }

    CriConfigEntry* configEntry = gCriConfigEntries;
    for (std::int32_t entryIndex = 0; entryIndex < gCriConfigEntryCount; ++entryIndex, ++configEntry) {
      if (configEntry->key[0] == '\0') {
        return configEntry;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00B104E0 (FUN_00B104E0, _CRICFG_Write)
   *
   * What it does:
   * Writes one 12-byte key/value pair into the next free CRI config entry.
   */
  std::int32_t CRICFG_Write(const char* const key, const std::int32_t value)
  {
    if (gCriConfigEntries == nullptr) {
      return -1;
    }

    CriConfigEntry* const configEntry = searchCfgInfoFree();
    if (configEntry == nullptr) {
      return -2;
    }

    std::strncpy(configEntry->key.data(), key, configEntry->key.size());
    configEntry->value = value;
    return 0;
  }

  /**
   * Address: 0x00B10580 (FUN_00B10580, _searchCfgInfo)
   *
   * What it does:
   * Searches one CRI config entry by 12-byte key lane and returns matching entry.
   */
  const CriConfigEntry* searchCfgInfo(const char* const key)
  {
    if (*key == '\0') {
      return nullptr;
    }
    if (gCriConfigEntryCount <= 0) {
      return nullptr;
    }

    const CriConfigEntry* configEntry = gCriConfigEntries;
    for (std::int32_t entryIndex = 0; entryIndex < gCriConfigEntryCount; ++entryIndex, ++configEntry) {
      if (std::strncmp(configEntry->key.data(), key, configEntry->key.size()) == 0) {
        return configEntry;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B10550 (FUN_00B10550, _CRICFG_Read)
   *
   * What it does:
   * Reads one integer CRI config value by key; returns `-1` when table is absent
   * and `-3` when key is not found.
   */
  std::int32_t CRICFG_Read(const char* const key, std::int32_t* const outValue)
  {
    if (gCriConfigEntries == nullptr) {
      return -1;
    }

    const CriConfigEntry* const configEntry = searchCfgInfo(key);
    if (configEntry == nullptr) {
      return -3;
    }

    *outValue = configEntry->value;
    return 0;
  }

  /**
   * Address: 0x00AE6D70 (FUN_00AE6D70, _UTY_InitTmr)
   *
   * What it does:
   * Initializes Sofdec timer-unit lane from `TMR_CH` config override or caller
   * fallback, then applies high-resolution counter scale when available.
   */
  std::int32_t UTY_InitTmr(const std::int32_t fallbackChannel)
  {
    std::int32_t configuredChannel = 0;
    if (CRICFG_Read(kUtyConfigTimerChannelKey, &configuredChannel) != 0) {
      configuredChannel = fallbackChannel;
    }

    ++gUtyTimerInitCount;
    if (gUtyTimerInitCount > 1 && gUtyTimerChannel == configuredChannel) {
      return configuredChannel;
    }

    gUtyTimerChannel = configuredChannel;
    if (configuredChannel != -1) {
      LARGE_INTEGER frequency{};
      if (QueryPerformanceFrequency(&frequency) != FALSE && frequency.QuadPart != 0) {
        return set_unit(frequency.QuadPart);
      }
    }

    return set_unit(1);
  }

  /**
   * Address: 0x00B03C70 (FUN_00B03C70, _UTY_SupportSse2)
   *
   * What it does:
   * Lazily initializes process-global SSE2 availability lane and returns it.
   */
  std::int32_t UTY_SupportSse2()
  {
    if (gUtySse2SupportState == -1) {
      _mm_empty();
      gUtySse2SupportState = 1;
    }
    return gUtySse2SupportState;
  }

  /**
   * Address: 0x00B03D50 (FUN_00B03D50, _UTY_SupportMmx)
   *
   * What it does:
   * Lazily initializes process-global MMX availability lane and returns it.
   */
  std::int32_t UTY_SupportMmx()
  {
    if (gUtyMmxSupportState == -1) {
      _mm_empty();
      gUtyMmxSupportState = 1;
    }
    return gUtyMmxSupportState;
  }

  /**
   * Address: 0x00B03CE0 (FUN_00B03CE0, _UTY_SupportSse)
   *
   * What it does:
   * Lazily initializes process-global SSE availability lane and returns it.
   */
  std::int32_t UTY_SupportSse()
  {
    if (gUtySseSupportState == -1) {
      _mm_empty();
      gUtySseSupportState = 1;
    }
    return gUtySseSupportState;
  }

  /**
   * Address: 0x00B031B0 (FUN_00B031B0, _cft_sse_Ycc420plnToRgb888Prg)
   *
   * What it does:
   * Converts YCC420 planar lanes to packed RGB888 using MMX lookup tables and
   * a two-stage scratch lane for chroma expansion + interleave.
   */
  std::uint8_t cft_sse_Ycc420plnToRgb888Prg(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface,
    const __m64* const colorTable,
    const std::uintptr_t scratchBufferAddress
  )
  {
    CFTCOM_SetCftFunctionName("cft_sse_Ycc420plnToRgb888Prg");

    const std::uint32_t alignedWidth = static_cast<std::uint32_t>(outputSurface->widthPixels + 15) & 0xFFFFFFF0u;
    const std::uintptr_t scratchPlaneBase =
      (scratchBufferAddress + 31u) & ~static_cast<std::uintptr_t>(31u);
    const std::uintptr_t interleavePlaneBase =
      (scratchPlaneBase + (8u * (alignedWidth >> 1)) + 31u) & ~static_cast<std::uintptr_t>(31u);

    std::uint8_t* yRow = inputLanes->yPlane;
    std::uint8_t* cbRow0 = inputLanes->cbPlane;
    std::uint8_t* cbRow1 = inputLanes->cbPlane + inputLanes->cbStrideBytes;
    std::uint8_t* crRow0 = inputLanes->crPlane;
    std::uint8_t* crRow1 = inputLanes->crPlane + inputLanes->crStrideBytes;
    std::uint8_t* outputRow = outputSurface->pixelBase;

    const __m64 kZero = _mm_setzero_si64();
    constexpr __m64 kAdjust = (__m64)0x0020002000200020LL;
    auto extractWord = [](const __m64 packed, const std::size_t wordIndex) -> std::uint32_t {
      const auto words = std::bit_cast<std::array<std::uint16_t, 4>>(packed);
      return words[wordIndex];
    };

    std::uint8_t result = static_cast<std::uint8_t>(interleavePlaneBase & 0xFFu);
    if (outputSurface->heightPixels != 0) {
      std::uint32_t remainingGroups = (static_cast<std::uint32_t>(outputSurface->heightPixels - 1) >> 2) + 1;
      do {
        const std::uint32_t halfWidth = alignedWidth >> 1;
        std::uint32_t blockCount = alignedWidth >> 4;
        auto* scratchCb = reinterpret_cast<std::uint64_t*>(scratchPlaneBase);
        auto* cbTop = reinterpret_cast<std::uint64_t*>(cbRow0);
        auto* cbBottom = reinterpret_cast<std::uint64_t*>(cbRow1);
        while (blockCount-- != 0u) {
          const std::uint64_t cbTopPack = *cbTop++;
          const std::uint64_t cbBottomPack = *cbBottom++;
          *scratchCb = cbTopPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCb) + halfWidth) = cbTopPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCb) + (2u * halfWidth)) = cbBottomPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCb) + (3u * halfWidth)) = cbBottomPack;
          ++scratchCb;
        }

        blockCount = alignedWidth >> 4;
        auto* scratchCr = reinterpret_cast<std::uint64_t*>(scratchPlaneBase + (4u * halfWidth));
        auto* crTop = reinterpret_cast<std::uint64_t*>(crRow0);
        auto* crBottom = reinterpret_cast<std::uint64_t*>(crRow1);
        while (blockCount-- != 0u) {
          const std::uint64_t crTopPack = *crTop++;
          const std::uint64_t crBottomPack = *crBottom++;
          *scratchCr = crTopPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCr) + halfWidth) = crTopPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCr) + (2u * halfWidth)) = crBottomPack;
          *reinterpret_cast<std::uint64_t*>(reinterpret_cast<std::uint8_t*>(scratchCr) + (3u * halfWidth)) = crBottomPack;
          ++scratchCr;
        }

        _m_empty();

        cbRow0 += 2 * inputLanes->cbStrideBytes;
        cbRow1 += 2 * inputLanes->cbStrideBytes;
        crRow0 += 2 * inputLanes->crStrideBytes;
        crRow1 += 2 * inputLanes->crStrideBytes;

        for (std::int32_t upsampleRow = 0; upsampleRow < 8; ++upsampleRow) {
          auto* upsampleDst = reinterpret_cast<__m64*>(interleavePlaneBase + (alignedWidth * upsampleRow));
          auto* upsampleSrc = reinterpret_cast<__m64*>(scratchPlaneBase + ((alignedWidth * upsampleRow) >> 1));
          std::int32_t laneBlocks = static_cast<std::int32_t>(alignedWidth >> 3) - 1;
          while (laneBlocks-- > 0) {
            const __m64 srcPack = *upsampleSrc;
            *upsampleDst = _m_punpcklbw(srcPack, _m_psrlqi(_m_pavgb(srcPack, _m_psllqi(srcPack, 8u)), 8u));
            upsampleSrc = reinterpret_cast<__m64*>(reinterpret_cast<std::uint8_t*>(upsampleSrc) + 4);
            ++upsampleDst;
          }

          const __m64 srcTail = *upsampleSrc;
          const __m64 carry = _m_psrlqi(_m_psllqi(_m_punpcklbw(_m_psrlqi(srcTail, 8u), kZero), 0x10u), 0x10u);
          *upsampleDst = _m_punpcklbw(
            srcTail,
            _m_packuswb(
              _m_pavgw(
                _m_punpcklbw(srcTail, kZero),
                _m_por(carry, _m_psllqi(_m_psrlqi(carry, 0x20u), 0x30u))
              ),
              kZero
            )
          );
        }

        _m_empty();

        std::uint8_t* interleaveRow = reinterpret_cast<std::uint8_t*>(interleavePlaneBase);
        std::int32_t rowsInGroup = 4;
        while (rowsInGroup-- > 0) {
          std::int32_t byteOffset = 0;
          while (byteOffset < static_cast<std::int32_t>(alignedWidth)) {
            const __m64 yPacked = *reinterpret_cast<const __m64*>(yRow + byteOffset);
            const __m64 cbPacked = *reinterpret_cast<const __m64*>(interleaveRow + byteOffset);
            const __m64 crPacked = *reinterpret_cast<const __m64*>(interleaveRow + (4u * alignedWidth) + byteOffset);

            std::uint8_t* dst = outputRow + (3 * byteOffset);
            for (std::size_t wordIndex = 0; wordIndex < 4; ++wordIndex) {
              const std::uint32_t yPair = extractWord(yPacked, wordIndex);
              const std::uint32_t cbPair = extractWord(cbPacked, wordIndex);
              const std::uint32_t crPair = extractWord(crPacked, wordIndex);

              const __m64 yLo = colorTable[yPair & 0xFFu];
              const __m64 yHi = colorTable[(yPair >> 8) & 0xFFu];
              const __m64 mixLo = _m_paddw(yLo, colorTable[256u + (cbPair & 0xFFu)]);
              const __m64 mixHi = _m_paddw(yHi, colorTable[256u + ((cbPair >> 8) & 0xFFu)]);
              const __m64 rgb = _m_packuswb(
                _m_psrawi(_m_paddw(_m_paddw(mixLo, colorTable[512u + (crPair & 0xFFu)]), kAdjust), 6u),
                _m_psrawi(_m_paddw(_m_paddw(mixHi, colorTable[512u + ((crPair >> 8) & 0xFFu)]), kAdjust), 6u)
              );

              const auto rgbWords = std::bit_cast<std::array<std::uint16_t, 4>>(rgb);
              const std::uint16_t pixel0Bg = rgbWords[0];
              const std::uint16_t pixel1Bg = rgbWords[2];
              dst[0] = static_cast<std::uint8_t>(pixel0Bg & 0xFFu);
              dst[1] = static_cast<std::uint8_t>(pixel0Bg >> 8);
              dst[2] = static_cast<std::uint8_t>(rgbWords[1] & 0xFFu);
              dst[3] = static_cast<std::uint8_t>(pixel1Bg & 0xFFu);
              dst[4] = static_cast<std::uint8_t>(pixel1Bg >> 8);
              dst[5] = static_cast<std::uint8_t>(rgbWords[3] & 0xFFu);
              dst += 6;
            }

            byteOffset += 8;
          }

          _m_empty();
          yRow += inputLanes->yStrideBytes;
          outputRow += outputSurface->strideBytes;
          interleaveRow += alignedWidth;
        }

        result = static_cast<std::uint8_t>(--remainingGroups);
      } while (remainingGroups != 0u);
    }

    return result;
  }

  /**
   * Address: 0x00B03DC0 (FUN_00B03DC0, _CFT_Ycc420plnToArgb8888Int1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample ARGB8888-int conversion lane based on
   * alignment/stride preconditions.
   */
  std::int32_t CFT_Ycc420plnToArgb8888Int1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface,
    const __m64* const colorTable
  )
  {
    if (UTY_SupportSse() == 0) {
      return cft_c_Ycc420plnToArgb8888Int1smp(inputLanes, outputSurface);
    }

    const std::uintptr_t alignmentMask =
      reinterpret_cast<std::uintptr_t>(outputSurface->pixelBase) |
      reinterpret_cast<std::uintptr_t>(inputLanes->yPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->cbPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->crPlane);
    if ((alignmentMask & 0x0Fu) != 0u) {
      return cft_c_Ycc420plnToArgb8888Int1smp(inputLanes, outputSurface);
    }

    if ((outputSurface->heightPixels & 3) != 0) {
      return cft_c_Ycc420plnToArgb8888Int1smp(inputLanes, outputSurface);
    }

    const std::int32_t widthPixels = outputSurface->widthPixels;
    const std::int32_t alignedWidthPixels = (widthPixels + 15) & ~15;
    if ((widthPixels & 0x0F) != 0 || std::abs(outputSurface->strideBytes) < (4 * alignedWidthPixels)) {
      return cft_c_Ycc420plnToArgb8888Int1smp(inputLanes, outputSurface);
    }

    return cft_sse_Ycc420plnToArgb8888Int1smp(inputLanes, outputSurface, colorTable);
  }

  /**
   * Address: 0x00B03E30 (FUN_00B03E30, _CFT_Ycc420plnToArgb8888Prg1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample ARGB8888-progressive conversion lane based
   * on alignment/stride preconditions.
   */
  std::int32_t CFT_Ycc420plnToArgb8888Prg1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface,
    const __m64* const colorTable
  )
  {
    if (UTY_SupportSse() == 0) {
      return cft_c_Ycc420plnToArgb8888Prg1smp(inputLanes, outputSurface);
    }

    const std::uintptr_t alignmentMask =
      reinterpret_cast<std::uintptr_t>(outputSurface->pixelBase) |
      reinterpret_cast<std::uintptr_t>(inputLanes->yPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->cbPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->crPlane);
    if ((alignmentMask & 0x0Fu) != 0u) {
      return cft_c_Ycc420plnToArgb8888Prg1smp(inputLanes, outputSurface);
    }

    if ((outputSurface->heightPixels & 3) != 0) {
      return cft_c_Ycc420plnToArgb8888Prg1smp(inputLanes, outputSurface);
    }

    const std::int32_t widthPixels = outputSurface->widthPixels;
    const std::int32_t alignedWidthPixels = (widthPixels + 15) & ~15;
    if ((widthPixels & 0x0F) != 0 || std::abs(outputSurface->strideBytes) < (4 * alignedWidthPixels)) {
      return cft_c_Ycc420plnToArgb8888Prg1smp(inputLanes, outputSurface);
    }

    return cft_sse_Ycc420plnToArgb8888Prg1smp(inputLanes, outputSurface, colorTable);
  }

  /**
   * Address: 0x00B03EA0 (FUN_00B03EA0, _CFT_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample YCC420->YCC422 pixel2/int conversion lane
   * based on alignment/stride preconditions.
   */
  std::int32_t CFT_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface
  )
  {
    if (UTY_SupportSse() == 0) {
      return static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(cft_c_Ycc420plnToYcc422pix2Int1smp(inputLanes, outputSurface))
      );
    }

    const std::uintptr_t alignmentMask =
      reinterpret_cast<std::uintptr_t>(outputSurface->pixelBase) |
      reinterpret_cast<std::uintptr_t>(inputLanes->yPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->cbPlane) |
      reinterpret_cast<std::uintptr_t>(inputLanes->crPlane);
    if ((alignmentMask & 0x0Fu) != 0u) {
      return static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(cft_c_Ycc420plnToYcc422pix2Int1smp(inputLanes, outputSurface))
      );
    }

    if ((outputSurface->heightPixels & 3) != 0) {
      return static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(cft_c_Ycc420plnToYcc422pix2Int1smp(inputLanes, outputSurface))
      );
    }

    const std::int32_t widthPixels = outputSurface->widthPixels;
    const std::int32_t alignedWidthPixels = (widthPixels + 15) & ~15;
    if ((widthPixels & 0x0F) != 0 || std::abs(outputSurface->strideBytes) < (2 * alignedWidthPixels)) {
      return static_cast<std::int32_t>(
        reinterpret_cast<std::intptr_t>(cft_c_Ycc420plnToYcc422pix2Int1smp(inputLanes, outputSurface))
      );
    }

    return cft_sse_Ycc420plnToYcc422pix2Int1smp(inputLanes, outputSurface);
  }

  /**
   * Address: 0x00B05180 (FUN_00B05180, _cft_c_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * Runs scalar YCC420 planar -> YCC422 pixel2/int1 conversion when MMX fast
   * path is unavailable or not selected.
   */
  std::uint8_t* cft_c_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface
  )
  {
    CFTCOM_SetCftFunctionName("cft_c_Ycc420plnToYcc422pix2Int1smp");

    auto packYuyvLane = [](const std::uint8_t y0, const std::uint8_t u, const std::uint8_t y1, const std::uint8_t v) -> std::uint32_t {
      return
        static_cast<std::uint32_t>(y0) |
        (static_cast<std::uint32_t>(u) << 8) |
        (static_cast<std::uint32_t>(y1) << 16) |
        (static_cast<std::uint32_t>(v) << 24);
    };

    std::int32_t processedRows = 0;
    const std::int32_t yStrideBytes = inputLanes->yStrideBytes;
    const std::int32_t cbStrideBytes = inputLanes->cbStrideBytes;
    const std::int32_t crStrideBytes = inputLanes->crStrideBytes;
    const std::int32_t oddWidthFlag = outputSurface->widthPixels & 1;
    const std::uint32_t roundedWidthPixels =
      static_cast<std::uint32_t>(outputSurface->widthPixels + oddWidthFlag);
    const std::uint32_t chromaPairsPerRow = roundedWidthPixels >> 1;

    const std::int32_t yTailAdvance = yStrideBytes - static_cast<std::int32_t>(roundedWidthPixels);
    const std::int32_t cbTailAdvance = cbStrideBytes - static_cast<std::int32_t>(chromaPairsPerRow);
    const std::int32_t crTailAdvance = crStrideBytes - static_cast<std::int32_t>(chromaPairsPerRow);
    const std::int32_t outputStrideBytes = outputSurface->strideBytes;
    const std::int32_t outputTailAdvance = outputStrideBytes - (2 * static_cast<std::int32_t>(roundedWidthPixels));
    const std::int32_t yGroupAdvance = (4 * yStrideBytes) - static_cast<std::int32_t>(roundedWidthPixels);
    const std::int32_t cbGroupAdvance = (2 * cbStrideBytes) - static_cast<std::int32_t>(chromaPairsPerRow);
    const std::int32_t crGroupAdvance = (2 * crStrideBytes) - static_cast<std::int32_t>(chromaPairsPerRow);
    const std::int32_t outputGroupAdvance = (4 * outputStrideBytes) - (2 * static_cast<std::int32_t>(roundedWidthPixels));

    std::uint8_t* yRow0 = inputLanes->yPlane;
    std::uint8_t* yRow1 = inputLanes->yPlane + yStrideBytes;
    std::uint8_t* yRow2 = inputLanes->yPlane + (2 * yStrideBytes);
    std::uint8_t* yRow3 = inputLanes->yPlane + (3 * yStrideBytes);
    std::uint8_t* cbRow0 = inputLanes->cbPlane;
    std::uint8_t* cbRow1 = inputLanes->cbPlane + cbStrideBytes;
    std::uint8_t* crRow0 = inputLanes->crPlane;
    std::uint8_t* crRow1 = inputLanes->crPlane + crStrideBytes;

    std::uint8_t* outputRow0 = outputSurface->pixelBase;
    std::uint8_t* outputRow1 = outputSurface->pixelBase + outputStrideBytes;
    std::uint8_t* outputRow2 = outputSurface->pixelBase + (2 * outputStrideBytes);
    std::uint8_t* outputRow3 = outputSurface->pixelBase + (3 * outputStrideBytes);

    if (outputSurface->heightPixels > 3) {
      std::int32_t guardRowIndex = 3;
      while (true) {
        if (chromaPairsPerRow != 0) {
          std::uint32_t pairCount = chromaPairsPerRow;
          auto* outPacked0 = reinterpret_cast<std::uint32_t*>(outputRow0);
          auto* outPacked1 = reinterpret_cast<std::uint32_t*>(outputRow1);
          auto* outPacked2 = reinterpret_cast<std::uint32_t*>(outputRow2);
          auto* outPacked3 = reinterpret_cast<std::uint32_t*>(outputRow3);

          do {
            const std::uint8_t y00 = *yRow0++;
            const std::uint8_t y01 = *yRow0++;
            const std::uint8_t y10 = *yRow1++;
            const std::uint8_t y11 = *yRow1++;
            const std::uint8_t y20 = *yRow2++;
            const std::uint8_t y21 = *yRow2++;
            const std::uint8_t y30 = *yRow3++;
            const std::uint8_t y31 = *yRow3++;

            const std::uint8_t cb0 = *cbRow0++;
            const std::uint8_t cb1 = *cbRow1++;
            const std::uint8_t cr0 = *crRow0++;
            const std::uint8_t cr1 = *crRow1++;

            *outPacked0++ = packYuyvLane(y00, cb0, y01, cr0);
            *outPacked1++ = packYuyvLane(y10, cb1, y11, cr1);
            *outPacked2++ = packYuyvLane(y20, cb0, y21, cr0);
            *outPacked3++ = packYuyvLane(y30, cb1, y31, cr1);
          } while (--pairCount != 0);

          outputRow0 = reinterpret_cast<std::uint8_t*>(outPacked0);
          outputRow1 = reinterpret_cast<std::uint8_t*>(outPacked1);
          outputRow2 = reinterpret_cast<std::uint8_t*>(outPacked2);
          outputRow3 = reinterpret_cast<std::uint8_t*>(outPacked3);
        }

        if (oddWidthFlag != 0) {
          outputRow0[-2] = outputRow0[-4];
          outputRow1[-2] = outputRow1[-4];
          outputRow2[-2] = outputRow2[-4];
          outputRow3[-2] = outputRow3[-4];
        }

        yRow0 += yGroupAdvance;
        yRow1 += yGroupAdvance;
        yRow2 += yGroupAdvance;
        yRow3 += yGroupAdvance;
        cbRow0 += cbGroupAdvance;
        cbRow1 += cbGroupAdvance;
        crRow0 += crGroupAdvance;
        crRow1 += crGroupAdvance;
        outputRow0 += outputGroupAdvance;
        outputRow1 += outputGroupAdvance;
        outputRow2 += outputGroupAdvance;
        outputRow3 += outputGroupAdvance;

        processedRows += 4;
        guardRowIndex += 4;
        if (guardRowIndex >= outputSurface->heightPixels) {
          break;
        }
      }
    }

    while (processedRows < outputSurface->heightPixels) {
      auto* outPacked = reinterpret_cast<std::uint32_t*>(outputRow0);
      if (chromaPairsPerRow != 0) {
        std::uint32_t pairCount = chromaPairsPerRow;
        do {
          const std::uint8_t y0 = *yRow0++;
          const std::uint8_t y1 = *yRow0++;
          const std::uint8_t cb = *cbRow0++;
          const std::uint8_t cr = *crRow0++;
          *outPacked++ = packYuyvLane(y0, cb, y1, cr);
        } while (--pairCount != 0);
      }

      outputRow0 = reinterpret_cast<std::uint8_t*>(outPacked);
      if (oddWidthFlag != 0) {
        outputRow0[-2] = outputRow0[-4];
      }

      yRow0 += yTailAdvance;
      cbRow0 += cbTailAdvance;
      crRow0 += crTailAdvance;
      outputRow0 += outputTailAdvance;
      ++processedRows;
    }

    return yRow0;
  }

  /**
   * Address: 0x00B062C0 (FUN_00B062C0, _cft_sse_Ycc420plnToArgb8888Prg1smp)
   *
   * What it does:
   * Converts one YCC420 planar frame to packed ARGB8888 using MMX lookup-table
   * lanes and writes two output scanlines per chroma row.
   */
  std::int32_t cft_sse_Ycc420plnToArgb8888Prg1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface,
    const __m64* const colorTable
  )
  {
    CFTCOM_SetCftFunctionName("cft_sse_Ycc420plnToArgb8888Prg1smp");

    std::int32_t result = outputSurface->heightPixels + 1;
    result &= ~1;

    const std::int32_t alignedChromaWordCount = ((outputSurface->widthPixels + 15) >> 1) & 0xFFFFFFF8;
    const std::int32_t yStrideBytes = inputLanes->yStrideBytes;
    const std::int32_t yPairStrideBytes = 2 * yStrideBytes;
    const std::int32_t outputStrideBytes = outputSurface->strideBytes;
    const std::int32_t outputPairStrideBytes = 2 * outputStrideBytes;

    std::uint8_t* yRow0 = inputLanes->yPlane;
    std::uint8_t* yRow1 = inputLanes->yPlane + yStrideBytes;
    std::uint8_t* cbRow = inputLanes->cbPlane;
    std::uint8_t* crRow = inputLanes->crPlane;
    std::uint8_t* outputRow0 = outputSurface->pixelBase;
    std::uint8_t* outputRow1 = outputSurface->pixelBase + outputStrideBytes;

    const __m64 kRoundBias = (__m64)0x0020002000200020LL;
    auto extractWord = [](const __m64 packed, const std::size_t wordIndex) -> std::uint32_t {
      const auto words = std::bit_cast<std::array<std::uint16_t, 4>>(packed);
      return words[wordIndex];
    };
    auto writePacked = [colorTable](std::uint8_t* const dst, const std::int32_t byteOffset, const __m64 chromaBase, const std::uint32_t yPair) {
      *reinterpret_cast<__m64*>(dst + byteOffset) = _m_packuswb(
        _m_psrawi(_m_paddw(chromaBase, colorTable[yPair & 0xFFu]), 6u),
        _m_psrawi(_m_paddw(chromaBase, colorTable[yPair >> 8]), 6u)
      );
    };

    if (result > 0) {
      unsigned int remainingRowPairs = static_cast<unsigned int>(((result - 1) >> 1) + 1);
      do {
        std::int32_t chromaWordOffset = 0;
        do {
          const __m64 cbWords = *reinterpret_cast<const __m64*>(cbRow + chromaWordOffset);
          const __m64 crWords = *reinterpret_cast<const __m64*>(crRow + chromaWordOffset);
          const __m64 yWordsRow0A = *reinterpret_cast<const __m64*>(yRow0 + 2 * chromaWordOffset);
          const __m64 yWordsRow1A = *reinterpret_cast<const __m64*>(yRow1 + 2 * chromaWordOffset);

          const std::uint32_t cbWord0 = extractWord(cbWords, 0);
          const __m64 cbMix0 = colorTable[256u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(cbWord0))];
          const __m64 cbMix1 = colorTable[256u + (cbWord0 >> 8)];
          const std::uint32_t crWord0 = extractWord(crWords, 0);
          const __m64 chromaBase0 = _m_paddw(
            _m_paddw(
              cbMix0,
              colorTable[512u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(crWord0))]
            ),
            kRoundBias
          );
          const __m64 chromaBase1 = _m_paddw(_m_paddw(cbMix1, colorTable[512u + (crWord0 >> 8)]), kRoundBias);

          const std::uint32_t yPair00 = extractWord(yWordsRow0A, 0);
          writePacked(outputRow0, 8 * chromaWordOffset, chromaBase0, yPair00);
          const std::uint32_t yPair10 = extractWord(yWordsRow1A, 0);
          writePacked(outputRow1, 8 * chromaWordOffset, chromaBase0, yPair10);

          const std::uint32_t yPair01 = extractWord(yWordsRow0A, 1);
          writePacked(outputRow0, 8 * chromaWordOffset + 8, chromaBase1, yPair01);
          const std::uint32_t yPair11 = extractWord(yWordsRow1A, 1);
          writePacked(outputRow1, 8 * chromaWordOffset + 8, chromaBase0, yPair11);

          const std::uint32_t cbWord1 = extractWord(cbWords, 1);
          const __m64 cbMix2 = colorTable[256u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(cbWord1))];
          const __m64 cbMix3 = colorTable[256u + (cbWord1 >> 8)];
          const std::uint32_t crWord1 = extractWord(crWords, 1);
          const __m64 chromaBase2 = _m_paddw(
            _m_paddw(
              cbMix2,
              colorTable[512u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(crWord1))]
            ),
            kRoundBias
          );
          const __m64 chromaBase3 = _m_paddw(_m_paddw(cbMix3, colorTable[512u + (crWord1 >> 8)]), kRoundBias);

          const std::uint32_t yPair02 = extractWord(yWordsRow0A, 2);
          writePacked(outputRow0, 8 * chromaWordOffset + 16, chromaBase2, yPair02);
          const std::uint32_t yPair12 = extractWord(yWordsRow1A, 2);
          writePacked(outputRow1, 8 * chromaWordOffset + 16, chromaBase2, yPair12);

          const std::uint32_t yPair03 = extractWord(yWordsRow0A, 3);
          writePacked(outputRow0, 8 * chromaWordOffset + 24, chromaBase3, yPair03);
          const std::uint32_t yPair13 = extractWord(yWordsRow1A, 3);
          writePacked(outputRow1, 8 * chromaWordOffset + 24, chromaBase2, yPair13);

          const __m64 yWordsRow0B = *reinterpret_cast<const __m64*>(yRow0 + 2 * chromaWordOffset + 8);
          const __m64 yWordsRow1B = *reinterpret_cast<const __m64*>(yRow1 + 2 * chromaWordOffset + 8);

          const std::uint32_t cbWord2 = extractWord(cbWords, 2);
          const __m64 cbMix4 = colorTable[256u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(cbWord2))];
          const __m64 cbMix5 = colorTable[256u + (cbWord2 >> 8)];
          const std::uint32_t crWord2 = extractWord(crWords, 2);
          const __m64 chromaBase4 = _m_paddw(
            _m_paddw(
              cbMix4,
              colorTable[512u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(crWord2))]
            ),
            kRoundBias
          );
          const __m64 chromaBase5 = _m_paddw(_m_paddw(cbMix5, colorTable[512u + (crWord2 >> 8)]), kRoundBias);

          const std::uint32_t yPair20 = extractWord(yWordsRow0B, 0);
          writePacked(outputRow0, 8 * chromaWordOffset + 32, chromaBase4, yPair20);
          const std::uint32_t yPair30 = extractWord(yWordsRow1B, 0);
          writePacked(outputRow1, 8 * chromaWordOffset + 32, chromaBase4, yPair30);

          const std::uint32_t yPair21 = extractWord(yWordsRow0B, 1);
          writePacked(outputRow0, 8 * chromaWordOffset + 40, chromaBase5, yPair21);
          const std::uint32_t yPair31 = extractWord(yWordsRow1B, 1);
          writePacked(outputRow1, 8 * chromaWordOffset + 40, chromaBase4, yPair31);

          const std::uint32_t cbWord3 = extractWord(cbWords, 3);
          const __m64 cbMix6 = colorTable[256u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(cbWord3))];
          const __m64 cbMix7 = colorTable[256u + (cbWord3 >> 8)];
          const std::uint32_t crWord3 = extractWord(crWords, 3);
          const __m64 chromaBase6 = _m_paddw(
            _m_paddw(
              cbMix6,
              colorTable[512u + static_cast<std::uint32_t>(static_cast<std::uint8_t>(crWord3))]
            ),
            kRoundBias
          );
          const __m64 chromaBase7 = _m_paddw(_m_paddw(cbMix7, colorTable[512u + (crWord3 >> 8)]), kRoundBias);

          const std::uint32_t yPair22 = extractWord(yWordsRow0B, 2);
          writePacked(outputRow0, 8 * chromaWordOffset + 48, chromaBase6, yPair22);
          const std::uint32_t yPair32 = extractWord(yWordsRow1B, 2);
          writePacked(outputRow1, 8 * chromaWordOffset + 48, chromaBase6, yPair32);

          const std::uint32_t yPair23 = extractWord(yWordsRow0B, 3);
          writePacked(outputRow0, 8 * chromaWordOffset + 56, chromaBase7, yPair23);
          const std::uint32_t yPair33 = extractWord(yWordsRow1B, 3);
          writePacked(outputRow1, 8 * chromaWordOffset + 56, chromaBase6, yPair33);

          chromaWordOffset += 8;
        } while (chromaWordOffset < alignedChromaWordCount);

        _m_empty();

        const std::int32_t chromaStrideBytes = inputLanes->cbStrideBytes;
        cbRow += chromaStrideBytes;
        crRow += chromaStrideBytes;
        yRow0 += yPairStrideBytes;
        result = static_cast<std::int32_t>(remainingRowPairs - 1);
        const bool isLastRowPair = remainingRowPairs == 1;
        yRow1 += yPairStrideBytes;
        outputRow0 += outputPairStrideBytes;
        outputRow1 += outputPairStrideBytes;
        --remainingRowPairs;
        if (isLastRowPair) {
          break;
        }
      } while (true);
    }

    return result;
  }

  /**
   * Address: 0x00B06770 (FUN_00B06770, _cft_sse_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * Converts YCC420 planar lanes to packed YCC422 pixel2/int1 layout using MMX
   * unpack/interleave operations in 4-line macroblock groups.
   */
  std::int32_t cft_sse_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* const inputLanes,
    const CftPixelSurfaceLanes* const outputSurface
  )
  {
    CFTCOM_SetCftFunctionName("cft_sse_Ycc420plnToYcc422pix2Int1smp");

    std::int32_t packedBlockCount = outputSurface->widthPixels + 15;
    packedBlockCount &= 0xFFFFFFF0;
    packedBlockCount /= 16;

    const std::int32_t rowGroupCount = outputSurface->heightPixels / 4;
    const std::int32_t yStrideBytes = inputLanes->yStrideBytes;
    const std::int32_t yStrideDouble = 2 * yStrideBytes;
    const std::int32_t yStrideQuad = 4 * yStrideBytes;
    const std::int32_t cbStrideDouble = 2 * inputLanes->cbStrideBytes;
    const std::int32_t outputStrideBytes = outputSurface->strideBytes;
    const std::int32_t outputStrideQuad = 4 * outputStrideBytes;

    std::uint8_t* outputRow0 = outputSurface->pixelBase;
    std::uint8_t* outputRow1 = outputSurface->pixelBase + outputStrideBytes;

    std::uint8_t* yRow0 = inputLanes->yPlane;
    std::uint8_t* yRow1 = inputLanes->yPlane + yStrideBytes;
    std::uint8_t* cbRow0 = inputLanes->cbPlane;
    std::uint8_t* cbRow1 = inputLanes->cbPlane + inputLanes->cbStrideBytes;
    std::uint8_t* crRow0 = inputLanes->crPlane;
    std::uint8_t* crRow1 = inputLanes->crPlane + inputLanes->crStrideBytes;

    std::int32_t result = rowGroupCount;
    if (rowGroupCount > 0) {
      std::int32_t remainingGroups = rowGroupCount;
      do {
        auto* cbPack = reinterpret_cast<__m64*>(cbRow0);
        auto* crPack = reinterpret_cast<__m64*>(crRow0);
        auto* yPackTop = reinterpret_cast<__m64*>(yRow0);
        auto* outPackTop = reinterpret_cast<__m64*>(outputRow0);
        std::int32_t block = packedBlockCount;
        while (block > 0) {
          const __m64 cbPacked = *cbPack++;
          const __m64 crPacked = *crPack++;
          const __m64 cbcrLo = _m_punpcklbw(cbPacked, crPacked);
          const __m64 cbcrHi = _m_punpckhbw(cbPacked, crPacked);

          const __m64 yTopLeft = yPackTop[0];
          const __m64 yTopRight = yPackTop[1];
          auto* yPackBottom = reinterpret_cast<__m64*>(reinterpret_cast<std::uint8_t*>(yPackTop) + yStrideDouble);

          outPackTop[0] = _m_punpcklbw(yTopLeft, cbcrLo);
          outPackTop[1] = _m_punpckhbw(yTopLeft, cbcrLo);
          outPackTop[2] = _m_punpcklbw(yTopRight, cbcrHi);
          outPackTop[3] = _m_punpckhbw(yTopRight, cbcrHi);

          const __m64 yBottomLeft = yPackBottom[0];
          const __m64 yBottomRight = yPackBottom[1];
          outPackTop[4] = _m_punpcklbw(yBottomLeft, cbcrLo);
          outPackTop[5] = _m_punpckhbw(yBottomLeft, cbcrLo);
          outPackTop[6] = _m_punpcklbw(yBottomRight, cbcrHi);
          outPackTop[7] = _m_punpckhbw(yBottomRight, cbcrHi);

          yPackTop = reinterpret_cast<__m64*>(reinterpret_cast<std::uint8_t*>(yPackBottom) - yStrideDouble + 16);
          outPackTop += 8;
          --block;
        }

        auto* cbPack2 = reinterpret_cast<__m64*>(cbRow1);
        auto* crPack2 = reinterpret_cast<__m64*>(crRow1);
        auto* yPackTop2 = reinterpret_cast<__m64*>(yRow1);
        auto* outPackTop2 = reinterpret_cast<__m64*>(outputRow1);
        block = packedBlockCount;
        while (block > 0) {
          const __m64 cbPacked = *cbPack2++;
          const __m64 crPacked = *crPack2++;
          const __m64 cbcrLo = _m_punpcklbw(cbPacked, crPacked);
          const __m64 cbcrHi = _m_punpckhbw(cbPacked, crPacked);

          const __m64 yTopLeft = yPackTop2[0];
          const __m64 yTopRight = yPackTop2[1];
          auto* yPackBottom = reinterpret_cast<__m64*>(reinterpret_cast<std::uint8_t*>(yPackTop2) + yStrideDouble);

          outPackTop2[0] = _m_punpcklbw(yTopLeft, cbcrLo);
          outPackTop2[1] = _m_punpckhbw(yTopLeft, cbcrLo);
          outPackTop2[2] = _m_punpcklbw(yTopRight, cbcrHi);
          outPackTop2[3] = _m_punpckhbw(yTopRight, cbcrHi);

          const __m64 yBottomLeft = yPackBottom[0];
          const __m64 yBottomRight = yPackBottom[1];
          outPackTop2[4] = _m_punpcklbw(yBottomLeft, cbcrLo);
          outPackTop2[5] = _m_punpckhbw(yBottomLeft, cbcrLo);
          outPackTop2[6] = _m_punpcklbw(yBottomRight, cbcrHi);
          outPackTop2[7] = _m_punpckhbw(yBottomRight, cbcrHi);

          yPackTop2 = reinterpret_cast<__m64*>(reinterpret_cast<std::uint8_t*>(yPackBottom) - yStrideDouble + 16);
          outPackTop2 += 8;
          --block;
        }

        _m_empty();

        yRow0 += yStrideQuad;
        yRow1 += yStrideQuad;
        cbRow0 += cbStrideDouble;
        cbRow1 += cbStrideDouble;
        crRow0 += cbStrideDouble;
        crRow1 += cbStrideDouble;
        outputRow0 += outputStrideQuad;
        outputRow1 += outputStrideQuad;

        result = remainingGroups - 1;
        --remainingGroups;
      } while (remainingGroups > 0);
    }

    return result;
  }

  /**
   * Address: 0x00AEE730 (FUN_00AEE730, _CFT_Ycc420plnToArgb8888IntInit)
   *
   * What it does:
   * Builds CFT integer lookup tables used by YCC420 planar -> ARGB8888
   * conversion lanes (packed intermediate, red, blue, and green tables).
   */
  void CFT_Ycc420plnToArgb8888IntInit()
  {
    auto clamp_round_to_byte = [](const double value) -> std::uint8_t {
      if (value < 0.0) {
        return 0;
      }
      if (value >= 255.0) {
        return 255;
      }
      return static_cast<std::uint8_t>(static_cast<std::int32_t>(value + 0.5));
    };

    std::size_t packedIndex = 0;
    for (std::int32_t yLane = -128; yLane < 128; ++yLane) {
      const double scaledY = static_cast<double>(yLane) * 1.596;
      for (std::int32_t cLane = -128; cLane < 128; ++cLane) {
        const double packedValue = static_cast<double>(cLane) * 2.017 + scaledY + 0.5;
        yuv_to_tmp[packedIndex] = static_cast<std::int16_t>(static_cast<std::int32_t>(std::floor(packedValue)) + 0x134);
        ++packedIndex;
      }
    }

    std::size_t redBlueIndex = 0;
    std::size_t greenIndex = 0;
    for (std::int32_t luma = 0; luma < 256; ++luma) {
      const double yTerm = static_cast<double>(luma - 16) * 1.164;
      for (std::int32_t chroma = -128; chroma < 128; ++chroma) {
        const std::uint8_t red = clamp_round_to_byte(static_cast<double>(chroma) * 1.596 + yTerm);
        yuv_to_r[redBlueIndex] = static_cast<std::uint32_t>(red) << 16;

        const std::uint8_t blue = clamp_round_to_byte(static_cast<double>(chroma) * 2.017 + yTerm);
        yuv_to_b[redBlueIndex] = blue;
        ++redBlueIndex;
      }

      const double doubledY = yTerm * 2.0;
      for (std::int32_t greenSource = -308; greenSource < 716; ++greenSource) {
        const std::uint8_t green = clamp_round_to_byte((doubledY - static_cast<double>(greenSource)) * 0.5);
        tmp_to_g[greenIndex] = static_cast<std::uint16_t>(static_cast<std::uint16_t>(green) << 8);
        ++greenIndex;
      }
    }
  }

  [[nodiscard]] std::int32_t buildBitcutClipTable32(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    const std::int32_t droppedBits = 8 - componentBits;
    std::memset(table, 0, 0x400u);

    for (std::uint32_t source = 0; source < 0x100u; ++source) {
      const std::int32_t clippedLane =
        static_cast<std::int32_t>(static_cast<std::int32_t>(source >> droppedBits) << bitShift);
      table[0x100u + source] = clippedLane | (clippedLane << 16);
    }

    const std::int32_t maxLane = static_cast<std::int32_t>((0xFF >> droppedBits) << bitShift);
    for (std::size_t index = 0; index < 0x100u; ++index) {
      table[0x200u + index] = maxLane;
    }

    return maxLane;
  }

  void buildBitcut5GradPatternDitherClipTable32(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    const std::int32_t droppedBits = 8 - componentBits;
    const std::int32_t maxLane = (1 << componentBits) - 1;
    std::memset(table, 0, 0x400u);

    for (std::int32_t source = 0; source < 0x100; ++source) {
      std::int32_t clippedLane = source >> droppedBits;
      if (clippedLane != maxLane) {
        const std::int32_t laneSpan = 1 << droppedBits;
        const std::int32_t threshold =
          static_cast<std::int32_t>(static_cast<double>((laneSpan * kCftDitherPatternWeights[ditherPatternIndex]) / 5) + 0.5);
        if ((source & (laneSpan - 1)) > threshold) {
          ++clippedLane;
        }
      }

      const std::int32_t shiftedLane = clippedLane << bitShift;
      table[0x100u + static_cast<std::size_t>(source)] = shiftedLane | (shiftedLane << 16);
    }

    const std::int32_t clippedMaxLane = static_cast<std::int32_t>((0xFF >> droppedBits) << bitShift);
    const std::int32_t clippedMaxPacked = clippedMaxLane | (clippedMaxLane << 16);
    for (std::size_t index = 0; index < 0x100u; ++index) {
      table[0x200u + index] = clippedMaxPacked;
    }
  }

  /**
   * Address: 0x00AF45F0 (FUN_00AF45F0, _createBitcutClipTable32_555)
   *
   * What it does:
   * Builds one RGB555 clip lookup table lane used by CFT color conversion.
   */
  std::int32_t createBitcutClipTable32_555(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    return buildBitcutClipTable32(table, componentBits, bitShift);
  }

  /**
   * Address: 0x00AF4660 (FUN_00AF4660, _createBitcut5GradPtnDitherClipTable32_555)
   *
   * What it does:
   * Builds one RGB555 dithered clip lookup lane for one 5-step pattern phase.
   */
  void createBitcut5GradPtnDitherClipTable32_555(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    buildBitcut5GradPatternDitherClipTable32(table, componentBits, bitShift, ditherPatternIndex);
  }

  /**
   * Address: 0x00AF56A0 (FUN_00AF56A0, _createBitcutClipTable32_565)
   *
   * What it does:
   * Builds one RGB565 clip lookup table lane used by CFT color conversion.
   */
  std::int32_t createBitcutClipTable32_565(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift
  )
  {
    return buildBitcutClipTable32(table, componentBits, bitShift);
  }

  /**
   * Address: 0x00AF5710 (FUN_00AF5710, _createBitcut5GradPtnDitherClipTable32_565)
   *
   * What it does:
   * Builds one RGB565 dithered clip lookup lane for one 5-step pattern phase.
   */
  void createBitcut5GradPtnDitherClipTable32_565(
    std::int32_t* const table,
    const std::int8_t componentBits,
    const std::int8_t bitShift,
    const std::int32_t ditherPatternIndex
  )
  {
    buildBitcut5GradPatternDitherClipTable32(table, componentBits, bitShift, ditherPatternIndex);
  }

  /**
   * Address: 0x00AF36B0 (FUN_00AF36B0, _CFT_Ycc420plnToRgb555Init)
   *
   * What it does:
   * Builds CFT RGB555 conversion and dither lookup tables used by YCC420
   * planar conversion paths.
   */
  void CFT_Ycc420plnToRgb555Init()
  {
    for (std::int32_t luma = 0; luma < 0x100; ++luma) {
      const double yTerm = (static_cast<double>(luma - 16) * 1.164 + 256.5) * kCftFixedPointScale;
      y_to_y2_555[static_cast<std::size_t>(luma)] = static_cast<std::int32_t>(yTerm);
    }

    for (std::int32_t index = 0; index < 0x100; ++index) {
      const double chromaLane = static_cast<double>(index - 128);
      cr_to_r_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(1.596 * chromaLane * kCftFixedPointScale);
      cb_to_g_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.392 * chromaLane * kCftFixedPointScale);
      cr_to_g_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.813 * chromaLane * kCftFixedPointScale);
      cb_to_b_555[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(2.017 * chromaLane * kCftFixedPointScale);
    }

    (void)createBitcutClipTable32_555(r_to_pix_555.data(), 5, 10);
    (void)createBitcutClipTable32_555(g_to_pix_555.data(), 5, 5);
    (void)createBitcutClipTable32_555(b_to_pix_555.data(), 5, 0);

    for (std::int32_t phase = 0; phase < 4; ++phase) {
      const std::size_t tableOffset = static_cast<std::size_t>(phase) * 0x300u;
      createBitcut5GradPtnDitherClipTable32_555(r_to_pix32_dither_555.data() + tableOffset, 5, 10, phase);
      createBitcut5GradPtnDitherClipTable32_555(g_to_pix32_dither_555.data() + tableOffset, 5, 5, phase);
      createBitcut5GradPtnDitherClipTable32_555(b_to_pix32_dither_555.data() + tableOffset, 5, 0, phase);
    }
  }

  /**
   * Address: 0x00AF4760 (FUN_00AF4760, _CFT_Ycc420plnToRgb565Init)
   *
   * What it does:
   * Builds CFT RGB565 conversion and dither lookup tables used by YCC420
   * planar conversion paths.
   */
  void CFT_Ycc420plnToRgb565Init()
  {
    for (std::int32_t luma = 0; luma < 0x100; ++luma) {
      const double yTerm = (static_cast<double>(luma - 16) * 1.164 + 256.5) * kCftFixedPointScale;
      y_to_y2_565[static_cast<std::size_t>(luma)] = static_cast<std::int32_t>(yTerm);
    }

    for (std::int32_t index = 0; index < 0x100; ++index) {
      const double chromaLane = static_cast<double>(index - 128);
      cr_to_r_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(1.596 * chromaLane * kCftFixedPointScale);
      cb_to_g_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.392 * chromaLane * kCftFixedPointScale);
      cr_to_g_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(0.813 * chromaLane * kCftFixedPointScale);
      cb_to_b_565[static_cast<std::size_t>(index)] =
        static_cast<std::int32_t>(2.017 * chromaLane * kCftFixedPointScale);
    }

    (void)createBitcutClipTable32_565(r_to_pix_565.data(), 5, 11);
    (void)createBitcutClipTable32_565(g_to_pix_565.data(), 6, 5);
    (void)createBitcutClipTable32_565(b_to_pix_565.data(), 5, 0);

    for (std::int32_t phase = 0; phase < 4; ++phase) {
      const std::size_t tableOffset = static_cast<std::size_t>(phase) * 0x300u;
      createBitcut5GradPtnDitherClipTable32_565(r_to_pix32_dither_565.data() + tableOffset, 5, 11, phase);
      createBitcut5GradPtnDitherClipTable32_565(g_to_pix32_dither_565.data() + tableOffset, 6, 5, phase);
      createBitcut5GradPtnDitherClipTable32_565(b_to_pix32_dither_565.data() + tableOffset, 5, 0, phase);
    }
  }

  /**
   * Address: 0x00ADE430 (FUN_00ADE430, _CFT_Finish)
   */
  void CFT_Finish()
  {
  }

  /**
   * Address: 0x00ADE440 (FUN_00ADE440, _CFTCOM_SetCftFunctionName)
   */
  const char* CFTCOM_SetCftFunctionName(const char* const functionName)
  {
    gCftcomFunctionName = functionName;
    return functionName;
  }

  /**
   * Address: 0x00ADE450 (FUN_00ADE450, _CFTCOM_GetCftFunctionName)
   */
  const char* CFTCOM_GetCftFunctionName()
  {
    return gCftcomFunctionName;
  }

  /**
   * Address: 0x00ADE460 (FUN_00ADE460, _CFT_OptimizeSpeed)
   */
  std::int32_t CFT_OptimizeSpeed(const std::int32_t optimizeSpeedMode)
  {
    gCftcomOptimizeSpeed = optimizeSpeedMode;
    return optimizeSpeedMode;
  }

  /**
   * Address: 0x00ACD100 (FUN_00ACD100, _SFX_SetHighSpeedConversion)
   *
   * What it does:
   * SFX-facing thunk that forwards conversion speed mode to CFT lane.
   */
  std::int32_t SFX_SetHighSpeedConversion(const std::int32_t optimizeSpeedMode)
  {
    return CFT_OptimizeSpeed(optimizeSpeedMode);
  }

  /**
   * Address: 0x00AC76F0 (FUN_00AC76F0, _mwPlySetHighSpeedConversion)
   *
   * What it does:
   * Playback-facing thunk that forwards high-speed conversion mode to SFX lane.
   */
  std::int32_t mwPlySetHighSpeedConversion(const std::int32_t optimizeSpeedMode)
  {
    return SFX_SetHighSpeedConversion(optimizeSpeedMode);
  }

  /**
   * Address: 0x00ADE470 (FUN_00ADE470, _CFTCOM_GetOptimizeSpeed)
   */
  std::int32_t CFTCOM_GetOptimizeSpeed()
  {
    return gCftcomOptimizeSpeed;
  }

  /**
   * Address: 0x00ADE480 (FUN_00ADE480, _SFXINF_GetStmInf)
   */
  std::int32_t SFXINF_GetStmInf(moho::SfxStreamState* const streamState, const char* const tagName)
  {
    (void)streamState;
    (void)tagName;
    return kSfxCompoModeHalfAlpha;
  }

  /**
   * Address: 0x00ADE490 (FUN_00ADE490, _SFBUF_Init)
   */
  std::int32_t SFBUF_Init()
  {
    return sfbuf_InitSjUuid();
  }

  /**
   * Address: 0x00ADE4A0 (FUN_00ADE4A0, _SFBUF_Finish)
   */
  void SFBUF_Finish()
  {
  }

  /**
   * Address: 0x00ADE1F0 (FUN_00ADE1F0, _SFXA_Finish)
   */
  void SFXA_Finish()
  {
  }

  /**
   * Address: 0x00ADE1D0 (FUN_00ADE1D0, _sfxalp_InitLibWork)
   */
  std::int32_t sfxalp_InitLibWork()
  {
    std::memset(&gSfxaLibWork, 0, sizeof(gSfxaLibWork));
    gSfxaLibWork.last = 0x20;
    return 0;
  }

  /**
   * Address: 0x00ADE1C0 (FUN_00ADE1C0, _SFXA_Init)
   *
   * What it does:
   * SFXA init thunk that forwards to `sfxalp_InitLibWork`.
   */
  std::int32_t SFXA_Init()
  {
    return sfxalp_InitLibWork();
  }

  /**
   * Address: 0x00ADE230 (FUN_00ADE230, _sfxamv_SearchFreeHn)
   */
  std::int32_t sfxamv_SearchFreeHn()
  {
    const std::int32_t maxHandleCount = gSfxaLibWork.last;
    if (maxHandleCount <= 0) {
      return 0;
    }

    auto* handleView = gSfxaLibWork.objects.data();
    for (std::int32_t index = 0; index < maxHandleCount; ++index, ++handleView) {
      if (handleView->used == 0) {
        return SjPointerToAddress(handleView);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00ADE200 (FUN_00ADE200, _SFXA_Create)
   */
  std::int32_t SFXA_Create()
  {
    const std::int32_t sfxaHandleAddress = sfxamv_SearchFreeHn();
    if (sfxaHandleAddress == 0) {
      return 0;
    }

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    (void)sfxamv_InitHn(sfxaHandleAddress);
    ++gSfxaLibWork.cur;
    handleView->used = 1;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE260 (FUN_00ADE260, _sfxamv_InitHn)
   */
  std::int32_t sfxamv_InitHn(const std::int32_t sfxaHandleAddress)
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->luminancePivot = 0;
    handleView->luminanceMin = 31;
    handleView->luminanceMax = 100;
    handleView->needsLumiTableUpdate = 1;
    handleView->alpha0 = 0;
    handleView->alpha1 = 127;
    handleView->alpha2 = -1;
    handleView->luminanceBuilder = nullptr;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE290 (FUN_00ADE290, _SFXA_Destroy)
   */
  void SFXA_Destroy(const std::int32_t sfxaHandleAddress)
  {
    if (sfxaHandleAddress == 0) {
      return;
    }

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->used = 0;
    --gSfxaLibWork.cur;
  }

  /**
   * Address: 0x00ADE2B0 (FUN_00ADE2B0, _SFXA_MakeAlpLumiTbl)
   */
  std::int32_t SFXA_MakeAlpLumiTbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = 0;
    if (handleView->luminanceBuilder != nullptr) {
      callbackResult = handleView->luminanceBuilder(
        handleView->luminancePivot,
        handleView->luminanceMin,
        handleView->luminanceMax,
        tableAddress
      );
    }
    handleView->needsLumiTableUpdate = 0;
    return callbackResult;
  }

  /**
   * Address: 0x00ADE2E0 (FUN_00ADE2E0, _SFXA_MakeAlp3110Tbl)
   */
  std::int32_t SFXA_MakeAlp3110Tbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = sfxaHandleAddress;
    if (handleView->alpha3110Builder != nullptr) {
      callbackResult = handleView->alpha3110Builder(
        tableAddress,
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha0)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha1)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha2))
      );
    }
    return callbackResult;
  }

  /**
   * Address: 0x00ADE310 (FUN_00ADE310, _SFXA_MakeAlp3211Tbl)
   */
  std::int32_t SFXA_MakeAlp3211Tbl(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t reservedMode,
    const std::int32_t tableAddress
  )
  {
    (void)reservedMode;

    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    std::int32_t callbackResult = sfxaHandleAddress;
    if (handleView->alpha3211Builder != nullptr) {
      callbackResult = handleView->alpha3211Builder(
        tableAddress,
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha0)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha1)),
        static_cast<std::int32_t>(static_cast<std::uint8_t>(handleView->alpha2))
      );
    }
    return callbackResult;
  }

  /**
   * Address: 0x00ADE340 (FUN_00ADE340, _SFXA_IsNeedUpdateLumiTbl)
   */
  std::int32_t SFXA_IsNeedUpdateLumiTbl(const std::int32_t sfxaHandleAddress)
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    return handleView->needsLumiTableUpdate;
  }

  /**
   * Address: 0x00ADE350 (FUN_00ADE350, _SFXA_SetLumiPrm)
   */
  std::int32_t SFXA_SetLumiPrm(
    const std::int32_t sfxaHandleAddress,
    const std::int32_t luminanceMin,
    const std::int32_t luminanceMax,
    const std::int32_t luminancePivot
  )
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->luminancePivot = luminancePivot;
    handleView->luminanceMin = luminanceMin;
    handleView->luminanceMax = luminanceMax;
    handleView->needsLumiTableUpdate = 1;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE380 (FUN_00ADE380, _SFXA_GetLumiPrm)
   */
  std::int32_t SFXA_GetLumiPrm(
    const std::int32_t sfxaHandleAddress,
    std::int32_t* const outLuminanceMin,
    std::int32_t* const outLuminanceMax,
    std::int32_t* const outLuminancePivot
  )
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    *outLuminancePivot = handleView->luminancePivot;
    *outLuminanceMin = handleView->luminanceMin;
    *outLuminanceMax = handleView->luminanceMax;
    return handleView->luminanceMax;
  }

  /**
   * Address: 0x00ADE3A0 (FUN_00ADE3A0, _SFXA_SetAlp3Prm)
   */
  std::int32_t SFXA_SetAlp3Prm(
    const std::int32_t sfxaHandleAddress,
    const std::int8_t alpha0,
    const std::int8_t alpha1,
    const std::int8_t alpha2
  )
  {
    auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    handleView->alpha0 = alpha0;
    handleView->alpha1 = alpha1;
    handleView->alpha2 = alpha2;
    return sfxaHandleAddress;
  }

  /**
   * Address: 0x00ADE3C0 (FUN_00ADE3C0, _SFXA_GetAlp3Prm)
   */
  std::int32_t SFXA_GetAlp3Prm(
    const std::int32_t sfxaHandleAddress,
    std::int8_t* const outAlpha0,
    std::int8_t* const outAlpha1,
    std::int8_t* const outAlpha2
  )
  {
    const auto* const handleView = reinterpret_cast<SfxaRuntimeHandleView*>(SjAddressToPointer(sfxaHandleAddress));
    *outAlpha0 = handleView->alpha0;
    *outAlpha1 = handleView->alpha1;
    *outAlpha2 = handleView->alpha2;
    return handleView->alpha2;
  }

  /**
   * Address: 0x00ADE3E0 (FUN_00ADE3E0, _SFXSUD_Init)
   */
  void SFXSUD_Init()
  {
    SUD_Init();
  }

  /**
   * Address: 0x00ADE3F0 (FUN_00ADE3F0, _SFXSUD_Finish)
   */
  std::int32_t SFXSUD_Finish()
  {
    return SUD_Finish();
  }

  /**
   * Address: 0x00ADE580 (FUN_00ADE580, _sfbuf_MakeBufPtr)
   */
  std::int32_t sfbuf_MakeBufPtr(
    std::int32_t* const outBufferPointers,
    const std::int32_t* const ringBufferSizes,
    std::int32_t baseBufferAddress
  )
  {
    constexpr std::int32_t kSfbufRingLaneCount = 8;
    for (std::int32_t lane = 0; lane < kSfbufRingLaneCount; ++lane) {
      outBufferPointers[lane] = baseBufferAddress;
      baseBufferAddress += ringBufferSizes[lane];
    }
    return baseBufferAddress;
  }

  /**
   * Address: 0x00ADE8E0 (FUN_00ADE8E0, _sfbuf_InitBufData)
   */
  std::int32_t* sfbuf_InitBufData(
    std::int32_t* const sfbufLaneWords,
    const std::int32_t laneType,
    const std::int32_t setupState
  )
  {
    auto* const laneView = reinterpret_cast<SfbufSupplyLaneView*>(sfbufLaneWords);
    laneView->laneType = laneType;
    laneView->isSetup = setupState;
    laneView->prepFlag = 0;
    laneView->termFlag = 0;
    laneView->runtimeState0 = 9;
    laneView->runtimeState1 = 9;
    return sfbufLaneWords;
  }

  /**
   * Address: 0x00ADE910 (FUN_00ADE910, _sfbuf_InitUoSj)
   */
  std::int32_t* sfbuf_InitUoSj(std::int32_t* const uoSjStateWords)
  {
    std::int32_t* cursor = uoSjStateWords + 2;
    for (std::int32_t block = 0; block < 3; ++block) {
      cursor[-2] = 0;
      cursor[-1] = 0;
      cursor[0] = 0;
      cursor[1] = 0;
      cursor += 4;
    }
    return cursor;
  }

  /**
   * Address: 0x00ADE8B0 (FUN_00ADE8B0, _sfbuf_InitUoSjBuf)
   */
  std::int32_t* sfbuf_InitUoSjBuf(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    (void)bufferAddressTable;
    (void)bufferSizeTable;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 3, 1);
    return sfbuf_InitUoSj(&laneView->sourceBufferAddress);
  }

  /**
   * Address: 0x00ADE7D0 (FUN_00ADE7D0, _sfbuf_InitAringBuf)
   */
  std::int32_t sfbuf_InitAringBuf(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t setupState = (bufferSizeTable[laneIndex] != 0) ? 1 : 0;
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 2, setupState);
    laneView->sourceBufferAddress = bufferAddressTable[laneIndex];
    const std::int32_t sourceBufferBytes = bufferSizeTable[laneIndex];
    laneView->laneParam18 = 0;
    laneView->queuedDataBytes = 0;
    laneView->laneParam20 = 0;
    laneView->laneParam24 = 0;
    laneView->delimiterPrimaryAddress = 0;
    laneView->delimiterSecondaryAddress = 0;
    laneView->writeTotalBytes = 0;
    laneView->readTotalBytes = 0;
    laneView->laneParam38 = 0;
    laneView->laneParam3C = 0;
    laneView->sourceBufferBytes = sourceBufferBytes;
    return sourceBufferBytes;
  }

  /**
   * Address: 0x00ADE740 (FUN_00ADE740, _sfbuf_InitVfrmBuf)
   */
  std::int32_t sfbuf_InitVfrmBuf(
    const std::int32_t vfrmOwnerAddress,
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex
  )
  {
    constexpr std::int32_t kVfrmScratchBaseOffset = 0x16B0;
    constexpr std::int32_t kVfrmScratchClearSpan = 0x880;
    constexpr std::int32_t kVfrmScratchStride = 0x88;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t setupState = (bufferSizeTable[laneIndex] != 0) ? 1 : 0;
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 1, setupState);
    laneView->sourceBufferAddress = bufferAddressTable[laneIndex];
    laneView->sourceBufferBytes = bufferSizeTable[laneIndex];
    laneView->laneParam18 = 0;
    laneView->queuedDataBytes = 0;
    laneView->laneParam20 = vfrmOwnerAddress + kVfrmScratchBaseOffset;

    std::int32_t scratchOffset = 0;
    while (scratchOffset < kVfrmScratchClearSpan) {
      auto* const scratchWord = reinterpret_cast<std::int32_t*>(SjAddressToPointer(laneView->laneParam20 + scratchOffset));
      *scratchWord = 0;
      scratchOffset += kVfrmScratchStride;
    }
    return scratchOffset;
  }

  /**
   * Address: 0x00ADE650 (FUN_00ADE650, _sfbuf_CreateSj)
   */
  std::int32_t sfbuf_CreateSj(
    std::int32_t* const outSjCreateStateWords,
    const std::int32_t sourceBufferAddress,
    const std::int32_t sourceBufferBytes,
    const std::int32_t extraBufferBytes
  )
  {
    constexpr std::int32_t kSfbufErrInvalidBufferSpan = -16776180;
    constexpr std::int32_t kSfbufErrCreateSjFailed = -16776182;

    auto* const createState = reinterpret_cast<SfbufSjCreateStateView*>(outSjCreateStateWords);
    createState->ownerTag = 0;
    createState->sourceBufferAddress = sourceBufferAddress;

    const std::int32_t sjBufferBytes = sourceBufferBytes - extraBufferBytes;
    createState->sourceBufferBytes = sjBufferBytes;
    if (sjBufferBytes <= 0) {
      return SFLIB_SetErr(0, kSfbufErrInvalidBufferSpan);
    }

    createState->extraBufferBytes = extraBufferBytes;
    createState->mUnknown14 = 0;
    createState->sjHandle = SJRBF_Create(sourceBufferAddress, sjBufferBytes, extraBufferBytes);
    if (createState->sjHandle != nullptr) {
      return 0;
    }
    return SFLIB_SetErr(0, kSfbufErrCreateSjFailed);
  }

  /**
   * Address: 0x00ADE5B0 (FUN_00ADE5B0, _sfbuf_InitRingSj)
   */
  std::int32_t sfbuf_InitRingSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const bufferAddressTable,
    const std::int32_t* const bufferSizeTable,
    const std::int32_t laneIndex,
    const std::int32_t extraBufferBytes
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const std::int32_t laneBufferBytes = bufferSizeTable[laneIndex];
    if (laneBufferBytes == 0) {
      (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 4, 0);
      return 0;
    }

    SfbufSjCreateStateView createState{};
    const std::int32_t status = sfbuf_CreateSj(
      reinterpret_cast<std::int32_t*>(&createState),
      bufferAddressTable[laneIndex],
      laneBufferBytes,
      extraBufferBytes
    );
    if (status != 0) {
      return status;
    }

    (void)sfbuf_SetSupSj(
      &laneView->sourceBufferAddress,
      reinterpret_cast<const std::int32_t*>(&createState),
      SjPointerToAddress(laneView),
      1
    );
    (void)sfbuf_InitBufData(reinterpret_cast<std::int32_t*>(laneView), 5, 1);
    return 0;
  }

  /**
   * Address: 0x00ADE4B0 (FUN_00ADE4B0, _SFBUF_InitHn)
   */
  std::int32_t SFBUF_InitHn(
    const std::int32_t vfrmOwnerAddress,
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const sfbufInitConfigWords
  )
  {
    constexpr std::int32_t kSfbufRingLane0 = 0;
    constexpr std::int32_t kSfbufRingLane1 = 1;
    constexpr std::int32_t kSfbufRingLane2 = 2;
    constexpr std::int32_t kSfbufVfrmLane0 = 3;
    constexpr std::int32_t kSfbufAringLane0 = 4;
    constexpr std::int32_t kSfbufVfrmLane1 = 5;
    constexpr std::int32_t kSfbufAringLane1 = 6;
    constexpr std::int32_t kSfbufUoSjLane = 7;

    const auto* const initConfig = reinterpret_cast<const SfbufInitLayoutConfigView*>(sfbufInitConfigWords);
    const std::int32_t* const laneBufferSizes = initConfig->laneBufferSizes.data();
    std::array<std::int32_t, 8> laneBufferAddresses{};
    (void)sfbuf_MakeBufPtr(laneBufferAddresses.data(), laneBufferSizes, initConfig->baseBufferAddress);

    std::int32_t status = sfbuf_InitRingSj(
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufRingLane0,
      laneBufferSizes[0] % initConfig->lane0ExtraModuloDivisor
    );
    if (status != 0) {
      return status;
    }

    status = sfbuf_InitRingSj(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufRingLane1, 0x800);
    if (status != 0) {
      return status;
    }

    status = sfbuf_InitRingSj(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufRingLane2, 0);
    if (status != 0) {
      return status;
    }

    (void)sfbuf_InitVfrmBuf(
      vfrmOwnerAddress,
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufVfrmLane0
    );
    (void)sfbuf_InitAringBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufAringLane0);
    (void)sfbuf_InitVfrmBuf(
      vfrmOwnerAddress,
      sfbufHandleAddress,
      laneBufferAddresses.data(),
      laneBufferSizes,
      kSfbufVfrmLane1
    );
    (void)sfbuf_InitAringBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufAringLane1);
    (void)sfbuf_InitUoSjBuf(sfbufHandleAddress, laneBufferAddresses.data(), laneBufferSizes, kSfbufUoSjLane);
    return 0;
  }

  /**
   * Address: 0x00ADE9C0 (FUN_00ADE9C0, _sfbuf_ChkSupSj)
   */
  std::int32_t sfbuf_ChkSupSj(const std::int32_t* const supplyDescriptorWords)
  {
    if (supplyDescriptorWords[1] == 0) {
      return -1;
    }
    if (supplyDescriptorWords[0] != 0) {
      return 0;
    }
    if (supplyDescriptorWords[2] == 0) {
      return -1;
    }
    if (supplyDescriptorWords[3] <= 0) {
      return -1;
    }
    if (supplyDescriptorWords[5] <= 0) {
      return 0;
    }
    return -1;
  }

  /**
   * Address: 0x00ADEAC0 (FUN_00ADEAC0, _sfbuf_InitConti)
   */
  std::int32_t* sfbuf_InitConti(std::int32_t* const continuityStateWords)
  {
    continuityStateWords[0] = 0;
    continuityStateWords[1] = 0;
    return continuityStateWords;
  }

  /**
   * Address: 0x00ADEA60 (FUN_00ADEA60, _sfbuf_SetSupSj)
   */
  void sfbuf_SetSupSj(
    std::int32_t* const supplyLaneWords,
    const std::int32_t* const supplyDescriptorWords,
    const std::int32_t ownerLaneAddress,
    const std::int32_t setupState
  )
  {
    SFLIB_LockCs();
    auto* const laneOwner = reinterpret_cast<SfbufSupplyLaneView*>(SjAddressToPointer(ownerLaneAddress));
    laneOwner->isSetup = setupState;

    for (std::int32_t laneWord = 0; laneWord < 6; ++laneWord) {
      supplyLaneWords[laneWord] = supplyDescriptorWords[laneWord];
    }
    (void)sfbuf_InitConti(supplyLaneWords + 6);
    supplyLaneWords[8] = 0;
    supplyLaneWords[9] = 0;
    for (std::int32_t laneWord = 0; laneWord < 5; ++laneWord) {
      supplyLaneWords[10 + laneWord] = 0;
    }

    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEA00 (FUN_00ADEA00, _sfbuf_SetSupplySjSub)
   */
  std::int32_t sfbuf_SetSupplySjSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t* const supplyDescriptorWords,
    const std::int32_t transferLaneIndex
  )
  {
    constexpr std::int32_t kSfbufLaneStateAwaitingSupply = 4;
    constexpr std::int32_t kSfbufErrLaneNotAwaitingSupply = -16776183;

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[transferLaneIndex];
    if (laneView->laneType != kSfbufLaneStateAwaitingSupply) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrLaneNotAwaitingSupply);
    }

    const std::int32_t setupState = (supplyDescriptorWords[1] != 0) ? 1 : 0;
    sfbuf_SetSupSj(
      &laneView->sourceBufferAddress,
      supplyDescriptorWords,
      SjPointerToAddress(laneView),
      setupState
    );
    return 0;
  }

  /**
   * Address: 0x00ADE930 (FUN_00ADE930, _SFBUF_SetSupplySj)
   */
  std::int32_t SFBUF_SetSupplySj(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const supplyDescriptorWords
  )
  {
    constexpr std::int32_t kSfbufErrInvalidSupplyDescriptor = -16776184;

    const std::int32_t sfbufHandleAddress = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(workctrlSubobj));
    if (sfbuf_ChkSupSj(supplyDescriptorWords) != 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrInvalidSupplyDescriptor);
    }

    if (SFTRN_IsSetup(workctrlSubobj, 1) != 0) {
      return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, 0);
    }
    if (SFTRN_IsSetup(workctrlSubobj, 2) != 0) {
      return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, 1);
    }

    const std::int32_t transferLaneIndex = (SFTRN_IsSetup(workctrlSubobj, 3) != 0) ? 2 : 0;
    return sfbuf_SetSupplySjSub(sfbufHandleAddress, supplyDescriptorWords, transferLaneIndex);
  }

  /**
   * Address: 0x00ADEAE0 (FUN_00ADEAE0, _SFBUF_SetUoch)
   */
  std::int32_t* SFBUF_SetUoch(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t uochSlotIndex,
    const std::int32_t* const chunkDescriptorWords
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    auto* const uochEntry = reinterpret_cast<SfbufUochDescriptorView*>(
      &laneView->sourceBufferAddress + (uochSlotIndex * 4)
    );
    uochEntry->word0 = chunkDescriptorWords[0];
    uochEntry->word1 = chunkDescriptorWords[1];
    uochEntry->word2 = chunkDescriptorWords[2];
    uochEntry->word3 = chunkDescriptorWords[3];
    return &uochEntry->word0;
  }

  /**
   * Address: 0x00ADEB30 (FUN_00ADEB30, _SFBUF_GetUoch)
   */
  std::int32_t SFBUF_GetUoch(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t uochSlotIndex,
    std::int32_t* const outChunkDescriptorWords
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    const auto* const uochEntry = reinterpret_cast<const SfbufUochDescriptorView*>(
      &laneView->sourceBufferAddress + (uochSlotIndex * 4)
    );
    outChunkDescriptorWords[0] = uochEntry->word0;
    outChunkDescriptorWords[1] = uochEntry->word1;
    outChunkDescriptorWords[2] = uochEntry->word2;
    outChunkDescriptorWords[3] = uochEntry->word3;
    return uochEntry->word3;
  }

  /**
   * Address: 0x00ADEB80 (FUN_00ADEB80, _SFBUF_GetRingSj)
   */
  std::int32_t SFBUF_GetRingSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    std::int32_t* const outRingHandleAddress
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    *outRingHandleAddress = runtimeView->lanes[laneIndex].sourceBufferBytes;
    return sfbufHandleAddress;
  }

  /**
   * Address: 0x00ADEBF0 (FUN_00ADEBF0, _sfbuf_RingGetSub)
   */
  std::int32_t sfbuf_RingGetSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursorWords,
    const std::int32_t laneMode
  )
  {
    auto* const outCursor = reinterpret_cast<SfbufRingCursorSnapshotView*>(outCursorWords);
    outCursor->firstChunk = {};
    outCursor->secondChunk = {};
    outCursor->reservedWords = {0, 0, 0};

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if ((laneView->isSetup != 0) && (laneView->sourceBufferBytes != 0)) {
      (void)sfbuf_PeekChunk(
        laneView->sourceBufferBytes,
        laneMode,
        &outCursor->firstChunk,
        &outCursor->secondChunk
      );
    }
    return 0;
  }

  /**
   * Address: 0x00ADECB0 (FUN_00ADECB0, _sfbuf_RingAddSub)
   */
  std::int32_t sfbuf_RingAddSub(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount,
    const std::int32_t laneMode
  )
  {
    constexpr std::int32_t kSfbufErrAdvanceMismatch = -16776181;

    std::int32_t status = 0;
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if ((advanceCount == 0) || (laneView->isSetup == 0) || (laneView->sourceBufferBytes == 0)) {
      return 0;
    }

    const std::int32_t movedBytes = sfbuf_MoveChunk(laneView->sourceBufferBytes, laneMode, advanceCount);
    if (movedBytes < advanceCount) {
      const std::int32_t remainingBytes = advanceCount - movedBytes;
      if (sfbuf_MoveChunk(laneView->sourceBufferBytes, laneMode, remainingBytes) < remainingBytes) {
        status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAdvanceMismatch);
      }
    }

    if (laneMode == 1) {
      if (ringIndex == 1) {
        (void)sfbuf_ResetConti(&laneView->sourceBufferAddress);
      }
      if (laneView->readTotalBytes >= 0) {
        laneView->readTotalBytes += advanceCount;
      }
    } else if (laneView->writeTotalBytes >= 0) {
      laneView->writeTotalBytes += advanceCount;
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return status;
  }

  /**
   * Address: 0x00ADEDA0 (FUN_00ADEDA0, _sfbuf_ResetConti)
   */
  std::uint32_t sfbuf_ResetConti(std::int32_t* const supplyStateWords)
  {
    auto* const supplyState = reinterpret_cast<SfbufSupplyStateWindowView*>(supplyStateWords);
    moho::SjChunkRange firstChunk{};
    moho::SjChunkRange secondChunk{};
    (void)sfbuf_PeekChunk(supplyState->ringHandleAddress, 1, &firstChunk, &secondChunk);

    const std::uint32_t delimiterAddress = static_cast<std::uint32_t>(supplyState->delimiterPrimaryAddress);
    if (
      !SfbufContainsAddress(firstChunk, delimiterAddress)
      && !SfbufContainsAddress(secondChunk, delimiterAddress)
    ) {
      supplyState->delimiterPrimaryAddress = 0;
      supplyState->delimiterSecondaryAddress = 0;
      return 0;
    }
    return delimiterAddress;
  }

  /**
   * Address: 0x00ADEE00 (FUN_00ADEE00, _sfbuf_PeekChunk)
   */
  std::int32_t sfbuf_PeekChunk(
    const std::int32_t ringHandleAddress,
    const std::int32_t laneMode,
    moho::SjChunkRange* const outFirstChunk,
    moho::SjChunkRange* const outSecondChunk
  )
  {
    constexpr std::int32_t kSfbufPeekAllBytes = 0x7FFFFFFF;

    auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(ringHandleAddress));
    const std::int32_t availableBytes = SJRBF_GetNumData(ringHandle, laneMode);
    SJRBF_GetChunk(ringHandle, laneMode, kSfbufPeekAllBytes, outFirstChunk);
    if (outFirstChunk->byteCount >= availableBytes) {
      outSecondChunk->bufferAddress = 0;
      outSecondChunk->byteCount = 0;
    } else {
      SJRBF_GetChunk(ringHandle, laneMode, kSfbufPeekAllBytes, outSecondChunk);
      SJRBF_UngetChunk(ringHandle, laneMode, outSecondChunk);
    }
    SJRBF_UngetChunk(ringHandle, laneMode, outFirstChunk);
    return availableBytes;
  }

  /**
   * Address: 0x00ADEE90 (FUN_00ADEE90, _sfbuf_MoveChunk)
   */
  std::int32_t sfbuf_MoveChunk(
    const std::int32_t ringHandleAddress,
    const std::int32_t laneMode,
    const std::int32_t requestedBytes
  )
  {
    auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(ringHandleAddress));
    moho::SjChunkRange chunk{};
    SJRBF_GetChunk(ringHandle, laneMode, requestedBytes, &chunk);
    const std::int32_t outputLane = (laneMode == 0) ? 1 : 0;
    SJRBF_PutChunk(ringHandle, outputLane, &chunk);
    return chunk.byteCount;
  }

  /**
   * Address: 0x00ADEBB0 (FUN_00ADEBB0, _SFBUF_RingGetWrite)
   */
  std::int32_t SFBUF_RingGetWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursor
  )
  {
    return sfbuf_RingGetSub(sfbufHandleAddress, ringIndex, outCursor, 0);
  }

  /**
   * Address: 0x00ADEBD0 (FUN_00ADEBD0, _SFBUF_RingGetRead)
   */
  std::int32_t SFBUF_RingGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outCursor
  )
  {
    return sfbuf_RingGetSub(sfbufHandleAddress, ringIndex, outCursor, 1);
  }

  /**
   * Address: 0x00ADEC80 (FUN_00ADEC80, _SFBUF_RingAddWrite)
   */
  std::int32_t SFBUF_RingAddWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount
  )
  {
    return sfbuf_RingAddSub(sfbufHandleAddress, ringIndex, advanceCount, 0);
  }

  /**
   * Address: 0x00ADEC90 (FUN_00ADEC90, _SFBUF_RingAddRead)
   */
  std::int32_t SFBUF_RingAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t advanceCount
  )
  {
    return sfbuf_RingAddSub(sfbufHandleAddress, ringIndex, advanceCount, 1);
  }

  /**
   * Address: 0x00ADEED0 (FUN_00ADEED0, _SFBUF_RingGetDlm)
   */
  void SFBUF_RingGetDlm(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outPrimaryDelimiterAddress,
    std::int32_t* const outSecondaryDelimiterAddress
  )
  {
    SFLIB_LockCs();
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    *outPrimaryDelimiterAddress = laneView->delimiterPrimaryAddress;
    *outSecondaryDelimiterAddress = laneView->delimiterSecondaryAddress;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEF20 (FUN_00ADEF20, _SFBUF_RingSetDlm)
   */
  void SFBUF_RingSetDlm(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t primaryDelimiterAddress,
    const std::int32_t secondaryDelimiterAddress
  )
  {
    SFLIB_LockCs();
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    laneView->delimiterPrimaryAddress = primaryDelimiterAddress;
    laneView->delimiterSecondaryAddress = secondaryDelimiterAddress;
    SFLIB_UnlockCs();
  }

  /**
   * Address: 0x00ADEFB0 (FUN_00ADEFB0, _SFBUF_GetWTot)
   */
  std::int32_t SFBUF_GetWTot(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    constexpr std::int32_t kSfbufTotalSaturated = 0x7FFFFFFF;

    SFLIB_LockCs();
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];

    std::int32_t totalWriteBytes = laneView->writeTotalBytes;
    const std::int32_t totalReadBytes = laneView->readTotalBytes;
    if (totalWriteBytes == 0) {
      if (totalReadBytes != 0) {
        auto* const ringHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(laneView->sourceBufferBytes));
        totalWriteBytes = totalReadBytes + SJRBF_GetNumData(ringHandle, 1);
      }
    }
    if (totalWriteBytes < 0) {
      totalWriteBytes = kSfbufTotalSaturated;
    }

    SFLIB_UnlockCs();
    return totalWriteBytes;
  }

  /**
   * Address: 0x00ADF020 (FUN_00ADF020, _SFBUF_RingGetSj)
   */
  std::int32_t SFBUF_RingGetSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outRingHandleAddress
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    *outRingHandleAddress = 0;
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }
    *outRingHandleAddress = laneView->sourceBufferBytes;
    return 0;
  }

  /**
   * Address: 0x00ADF070 (FUN_00ADF070, _SFBUF_AddRtotSj)
   */
  std::int32_t* SFBUF_AddRtotSj(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addBytes
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->readTotalBytes >= 0) {
      laneView->readTotalBytes += addBytes;
    }
    return &laneView->sourceBufferAddress;
  }

  /**
   * Address: 0x00ADF0A0 (FUN_00ADF0A0, _SFBUF_AringGetWrite)
   */
  std::int32_t SFBUF_AringGetWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outAringSnapshotWords
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    SFLIB_LockCs();
    const auto* const aringState = reinterpret_cast<const SfbufAringLaneStateView*>(&laneView->laneParam18);
    const std::int32_t transferParam0 = aringState->transferParam0;
    const std::int32_t sampleMode = aringState->sampleMode;
    const std::int32_t transferParam2 = aringState->transferParam2;
    const std::int32_t primarySampleBaseAddress = aringState->primarySampleBaseAddress;
    const std::int32_t secondarySampleBaseAddress = aringState->secondarySampleBaseAddress;
    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    const std::int32_t writeCursorSamples = aringState->writeCursorSamples;
    const std::int32_t readCursorSamples = aringState->readCursorSamples;
    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t readTotalSamples = aringState->readTotalSamples;
    SFLIB_UnlockCs();

    auto* const outSnapshot = reinterpret_cast<SfbufAringTransferSnapshotView*>(outAringSnapshotWords);
    outSnapshot->transferParam0 = transferParam0;
    outSnapshot->sampleMode = sampleMode;
    outSnapshot->transferParam2 = transferParam2;
    outSnapshot->writeTotalSamples = writeTotalSamples;
    outSnapshot->readTotalSamples = readTotalSamples;

    if (writeTotalSamples < (ringCapacitySamples + readTotalSamples)) {
      if (writeCursorSamples >= readCursorSamples) {
        outSnapshot->chunkSampleCount = ringCapacitySamples - writeCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, writeCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, writeCursorSamples);
        outSnapshot->wrapCursorSample = readCursorSamples;
        outSnapshot->primaryWrapAddress = primarySampleBaseAddress;
        outSnapshot->secondaryWrapAddress = secondarySampleBaseAddress;
      } else {
        outSnapshot->chunkSampleCount = readCursorSamples - writeCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, writeCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, writeCursorSamples);
        outSnapshot->wrapCursorSample = 0;
        outSnapshot->primaryWrapAddress = 0;
        outSnapshot->secondaryWrapAddress = 0;
      }
    } else {
      outSnapshot->chunkSampleCount = 0;
      outSnapshot->primaryChunkAddress = 0;
      outSnapshot->secondaryChunkAddress = 0;
      outSnapshot->wrapCursorSample = 0;
      outSnapshot->primaryWrapAddress = 0;
      outSnapshot->secondaryWrapAddress = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADF220 (FUN_00ADF220, _SFBUF_AringAddWrite)
   */
  std::int32_t SFBUF_AringAddWrite(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addSamples
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;
    constexpr std::int32_t kSfbufErrAringWriteOverflow = -16776186;

    if (addSamples == 0) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    std::int32_t status = 0;
    SFLIB_LockCs();
    auto* const aringState = reinterpret_cast<SfbufAringLaneStateView*>(&laneView->laneParam18);

    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    std::int32_t nextWriteCursor = addSamples + aringState->writeCursorSamples;
    if (nextWriteCursor >= ringCapacitySamples) {
      nextWriteCursor -= ringCapacitySamples;
    }
    aringState->writeCursorSamples = nextWriteCursor;

    const std::int32_t nextWriteTotal = addSamples + aringState->writeTotalSamples;
    const std::int32_t maxWriteTotal = ringCapacitySamples + aringState->readTotalSamples;
    aringState->writeTotalSamples = nextWriteTotal;
    if (nextWriteTotal > maxWriteTotal) {
      status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAringWriteOverflow);
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    SFLIB_UnlockCs();
    return status;
  }

  /**
   * Address: 0x00ADF2D0 (FUN_00ADF2D0, _SFBUF_AringGetRead)
   */
  std::int32_t SFBUF_AringGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    std::int32_t* const outAringSnapshotWords
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;

    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    SFLIB_LockCs();
    const auto* const aringState = reinterpret_cast<const SfbufAringLaneStateView*>(&laneView->laneParam18);
    const std::int32_t transferParam0 = aringState->transferParam0;
    const std::int32_t sampleMode = aringState->sampleMode;
    const std::int32_t transferParam2 = aringState->transferParam2;
    const std::int32_t primarySampleBaseAddress = aringState->primarySampleBaseAddress;
    const std::int32_t secondarySampleBaseAddress = aringState->secondarySampleBaseAddress;
    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    const std::int32_t writeCursorSamples = aringState->writeCursorSamples;
    const std::int32_t readCursorSamples = aringState->readCursorSamples;
    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t readTotalSamples = aringState->readTotalSamples;
    SFLIB_UnlockCs();

    auto* const outSnapshot = reinterpret_cast<SfbufAringTransferSnapshotView*>(outAringSnapshotWords);
    outSnapshot->transferParam0 = transferParam0;
    outSnapshot->sampleMode = sampleMode;
    outSnapshot->transferParam2 = transferParam2;
    outSnapshot->writeTotalSamples = writeTotalSamples;
    outSnapshot->readTotalSamples = readTotalSamples;

    if (writeTotalSamples > readTotalSamples) {
      if (readCursorSamples >= writeCursorSamples) {
        outSnapshot->chunkSampleCount = ringCapacitySamples - readCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, readCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, readCursorSamples);
        outSnapshot->wrapCursorSample = writeCursorSamples;
        outSnapshot->primaryWrapAddress = primarySampleBaseAddress;
        outSnapshot->secondaryWrapAddress = secondarySampleBaseAddress;
      } else {
        outSnapshot->chunkSampleCount = writeCursorSamples - readCursorSamples;
        outSnapshot->primaryChunkAddress = SfbufAringScaledAddress(sampleMode, primarySampleBaseAddress, readCursorSamples);
        outSnapshot->secondaryChunkAddress = SfbufAringScaledAddress(sampleMode, secondarySampleBaseAddress, readCursorSamples);
        outSnapshot->wrapCursorSample = 0;
        outSnapshot->primaryWrapAddress = 0;
        outSnapshot->secondaryWrapAddress = 0;
      }
    } else {
      outSnapshot->chunkSampleCount = 0;
      outSnapshot->primaryChunkAddress = 0;
      outSnapshot->secondaryChunkAddress = 0;
      outSnapshot->wrapCursorSample = 0;
      outSnapshot->primaryWrapAddress = 0;
      outSnapshot->secondaryWrapAddress = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00ADF450 (FUN_00ADF450, _SFBUF_AringAddRead)
   */
  std::int32_t SFBUF_AringAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t ringIndex,
    const std::int32_t addSamples
  )
  {
    constexpr std::int32_t kSfbufErrRingNotSetup = -16776191;
    constexpr std::int32_t kSfbufErrAringReadOverflow = -16776185;

    if (addSamples == 0) {
      return 0;
    }

    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    SfbufSupplyLaneView* const laneView = &runtimeView->lanes[ringIndex];
    if (laneView->isSetup == 0) {
      return SFLIB_SetErr(sfbufHandleAddress, kSfbufErrRingNotSetup);
    }

    std::int32_t status = 0;
    SFLIB_LockCs();
    auto* const aringState = reinterpret_cast<SfbufAringLaneStateView*>(&laneView->laneParam18);

    const std::int32_t ringCapacitySamples = aringState->ringCapacitySamples;
    std::int32_t nextReadCursor = addSamples + aringState->readCursorSamples;
    if (nextReadCursor >= ringCapacitySamples) {
      nextReadCursor -= ringCapacitySamples;
    }
    aringState->readCursorSamples = nextReadCursor;

    const std::int32_t writeTotalSamples = aringState->writeTotalSamples;
    const std::int32_t nextReadTotal = addSamples + aringState->readTotalSamples;
    aringState->readTotalSamples = nextReadTotal;
    if (nextReadTotal > writeTotalSamples) {
      status = SFLIB_SetErr(sfbufHandleAddress, kSfbufErrAringReadOverflow);
    }

    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    SFLIB_UnlockCs();
    return status;
  }

  /**
   * Address: 0x00ADF500 (FUN_00ADF500, _SFBUF_VfrmGetWrite)
   */
  std::int32_t SFBUF_VfrmGetWrite()
  {
    return 0;
  }

  /**
   * Address: 0x00ADF510 (FUN_00ADF510, _SFBUF_VfrmAddWrite)
   */
  std::int32_t SFBUF_VfrmAddWrite(const std::int32_t sfbufHandleAddress)
  {
    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return 0;
  }

  /**
   * Address: 0x00ADF520 (FUN_00ADF520, _SFBUF_VfrmGetRead)
   */
  std::int32_t SFBUF_VfrmGetRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    if (laneView->isSetup != 0) {
      return 0;
    }
    return SFTRN_CallTrtTrif(sfbufHandleAddress, laneView->runtimeState0, 11, arg0, arg1);
  }

  /**
   * Address: 0x00ADF570 (FUN_00ADF570, _SFBUF_VfrmAddRead)
   */
  std::int32_t SFBUF_VfrmAddRead(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t arg0,
    const std::int32_t arg1
  )
  {
    std::int32_t result = 0;
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    const SfbufSupplyLaneView* const laneView = &runtimeView->lanes[laneIndex];
    if (laneView->isSetup == 0) {
      result = SFTRN_CallTrtTrif(sfbufHandleAddress, laneView->runtimeState0, 12, arg0, arg1);
    }
    auto* const runtimeStatus = reinterpret_cast<SfbufRuntimeStatusView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeStatus->dirtyFlag = 1;
    return result;
  }

  /**
   * Address: 0x00ADF5C0 (FUN_00ADF5C0, _SFBUF_SetPrepFlg)
   */
  std::int32_t SFBUF_SetPrepFlg(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t prepFlag
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeView->lanes[laneIndex].prepFlag = prepFlag;
    return prepFlag;
  }

  /**
   * Address: 0x00ADF5E0 (FUN_00ADF5E0, _SFBUF_GetPrepFlg)
   */
  std::int32_t SFBUF_GetPrepFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[laneIndex].prepFlag;
  }

  /**
   * Address: 0x00ADF600 (FUN_00ADF600, _SFBUF_SetTermFlg)
   */
  std::int32_t SFBUF_SetTermFlg(
    const std::int32_t sfbufHandleAddress,
    const std::int32_t laneIndex,
    const std::int32_t termFlag
  )
  {
    auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    runtimeView->lanes[laneIndex].termFlag = termFlag;
    return termFlag;
  }

  /**
   * Address: 0x00ADF620 (FUN_00ADF620, _SFBUF_GetTermFlg)
   */
  std::int32_t SFBUF_GetTermFlg(const std::int32_t sfbufHandleAddress, const std::int32_t laneIndex)
  {
    const auto* const runtimeView = reinterpret_cast<SfbufRuntimeHandleView*>(SjAddressToPointer(sfbufHandleAddress));
    return runtimeView->lanes[laneIndex].termFlag;
  }

  /**
   * Address: 0x00ADF640 (FUN_00ADF640, _SFBUF_GetRingBufSiz)
   */
  std::int32_t SFBUF_GetRingBufSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    SfbufRingCursorSnapshotView ringSnapshot{};
    (void)SFBUF_RingGetRead(sfbufHandleAddress, ringIndex, reinterpret_cast<std::int32_t*>(&ringSnapshot));
    return ringSnapshot.firstChunk.byteCount + ringSnapshot.secondChunk.byteCount;
  }

  /**
   * Address: 0x00ADF670 (FUN_00ADF670, _SFBUF_RingGetFreeSiz)
   */
  std::int32_t SFBUF_RingGetFreeSiz(const std::int32_t sfbufHandleAddress, const std::int32_t ringIndex)
  {
    SfbufRingCursorSnapshotView ringSnapshot{};
    (void)SFBUF_RingGetWrite(sfbufHandleAddress, ringIndex, reinterpret_cast<std::int32_t*>(&ringSnapshot));
    return ringSnapshot.firstChunk.byteCount + ringSnapshot.secondChunk.byteCount;
  }

  /**
   * Address: 0x00ADF720 (FUN_00ADF720, _sfbuf_InitSjUuid)
   */
  std::int32_t sfbuf_InitSjUuid()
  {
    constexpr std::int32_t kProbeBufferBytes = 8;
    std::array<std::int32_t, 2> probeBufferWords{};

    auto* const ringBufferHandle =
      SJRBF_Create(SjPointerToAddress(probeBufferWords.data()), kProbeBufferBytes, 0);
    gSfbufSjRingBufferUuid = SJRBF_GetUuid(ringBufferHandle);
    SJRBF_Destroy(ringBufferHandle);

    auto* const memoryHandle = SJMEM_Create(SjPointerToAddress(probeBufferWords.data()), kProbeBufferBytes);
    gSfbufSjMemoryUuid = SJMEM_GetUuid(memoryHandle);
    SJMEM_Destroy(memoryHandle);
    return 0;
  }

  /**
   * Address: 0x00ADF770 (FUN_00ADF770, _sfbuf_IsSjRbf)
   */
  std::int32_t sfbuf_IsSjRbf(const std::int32_t sjHandleAddress)
  {
    auto* const ringBufferHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(sjHandleAddress));
    return (SJRBF_GetUuid(ringBufferHandle) == gSfbufSjRingBufferUuid) ? 1 : 0;
  }

  /**
   * Address: 0x00ADF790 (FUN_00ADF790, _sfbuf_IsSjMem)
   */
  std::int32_t sfbuf_IsSjMem(const std::int32_t sjHandleAddress)
  {
    auto* const memoryHandle = reinterpret_cast<moho::SofdecSjMemoryHandle*>(SjAddressToPointer(sjHandleAddress));
    return (SJMEM_GetUuid(memoryHandle) == gSfbufSjMemoryUuid) ? 1 : 0;
  }

  /**
   * Address: 0x00ADF6A0 (FUN_00ADF6A0, _SFBUF_GetFlowCnt)
   */
  std::int32_t SFBUF_GetFlowCnt(
    const std::int32_t sjHandleAddress,
    std::int32_t* const outLane1FlowCount,
    std::int32_t* const outLane0FlowCount
  )
  {
    if (sfbuf_IsSjRbf(sjHandleAddress) != 0) {
      auto* const ringBufferHandle = reinterpret_cast<moho::SofdecSjRingBufferHandle*>(SjAddressToPointer(sjHandleAddress));
      *outLane1FlowCount = SJRBF_GetFlowCnt(ringBufferHandle, 1, 1);
      const std::int32_t lane0FlowCount = SJRBF_GetFlowCnt(ringBufferHandle, 0, 1);
      *outLane0FlowCount = lane0FlowCount;
      return lane0FlowCount;
    }

    if (sfbuf_IsSjMem(sjHandleAddress) != 0) {
      auto* const memoryHandle = reinterpret_cast<moho::SofdecSjMemoryHandle*>(SjAddressToPointer(sjHandleAddress));
      *outLane1FlowCount = SJMEM_GetBufSize(memoryHandle);
      const std::int32_t pendingBytes = SJMEM_GetNumData(memoryHandle, 1);
      *outLane0FlowCount = *outLane1FlowCount - pendingBytes;
      return pendingBytes;
    }

    *outLane1FlowCount = 0;
    *outLane0FlowCount = 0;
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outLane1FlowCount));
  }

  /**
   * Address: 0x00ADF7B0 (FUN_00ADF7B0, _SFBUF_UpdateFlowCnt)
   */
  std::int64_t SFBUF_UpdateFlowCnt(
    const std::int32_t previousFlowLow,
    const std::int32_t previousFlowHigh,
    const std::int32_t nextFlowLow
  )
  {
    const std::uint32_t previousLow = static_cast<std::uint32_t>(previousFlowLow);
    const std::uint32_t nextLow = static_cast<std::uint32_t>(nextFlowLow);
    const std::uint32_t nextHigh = static_cast<std::uint32_t>(previousFlowHigh) + ((nextLow < previousLow) ? 1u : 0u);
    return static_cast<std::int64_t>((static_cast<std::uint64_t>(nextHigh) << 32u) | nextLow);
  }

  /**
   * Address: 0x00ADF7F0 (FUN_00ADF7F0, _SFTRN_Init)
   */
  std::int32_t SFTRN_Init(void* const outTransferEntryTable, void* const transferEntryTable)
  {
    auto* const outEntryList = reinterpret_cast<SftrnEntryListView*>(outTransferEntryTable);
    auto* const sourceEntryList = reinterpret_cast<SftrnEntryListView*>(transferEntryTable);
    std::memcpy(outEntryList, sourceEntryList, sizeof(SftrnEntryListView));
    return sftrn_CallTrEntry(sourceEntryList, 0);
  }

  /**
   * Address: 0x00ADF820 (FUN_00ADF820, _SFTRN_Finish)
   */
  std::int32_t SFTRN_Finish(void* const transferEntryTable)
  {
    return sftrn_CallTrEntry(transferEntryTable, 1);
  }

  /**
   * Address: 0x00ADF830 (FUN_00ADF830, _sftrn_CallTrEntry)
   */
  std::int32_t sftrn_CallTrEntry(void* const transferEntryTable, const std::int32_t entrySelector)
  {
    auto* const entryList = reinterpret_cast<SftrnEntryListView*>(transferEntryTable);
    std::int32_t result = 0;
    for (std::int32_t entryIndex = 0; entryIndex < static_cast<std::int32_t>(entryList->entries.size()); ++entryIndex) {
      SftrnEntryDispatchView* const entryDispatch = entryList->entries[entryIndex];
      if (entryDispatch == nullptr) {
        break;
      }
      result = entryDispatch->entryCallbacks[entrySelector](0, 0, 0, 0);
      if (result != 0) {
        break;
      }
    }
    return result;
  }

  /**
   * Address: 0x00ADF870 (FUN_00ADF870, _SFTRN_InitHn)
   */
  std::int32_t SFTRN_InitHn(
    const std::int32_t workctrlAddress,
    const std::int32_t transferDataArrayAddress,
    const std::int32_t* const transferBuildConfigAddressPtr
  )
  {
    constexpr std::int32_t kSftrnTransferLaneCount = 9;
    constexpr std::int32_t kSftrnErrBuildFailed = -16776446;

    const std::int32_t transferBuildConfigAddress = *transferBuildConfigAddressPtr;
    auto* const transferLanes = reinterpret_cast<SftrnTransferDataLaneView*>(SjAddressToPointer(transferDataArrayAddress));
    const auto* const transferBuildConfigWords =
      reinterpret_cast<const std::int32_t*>(SjAddressToPointer(transferBuildConfigAddress));

    for (std::int32_t laneIndex = 0; laneIndex < kSftrnTransferLaneCount; ++laneIndex) {
      transferLanes[laneIndex].setupState = 0;
      (void)sftrn_InitTrData(
        reinterpret_cast<std::int32_t*>(&transferLanes[laneIndex]),
        transferBuildConfigWords[laneIndex]
      );
    }

    auto* const workctrlSubobj = reinterpret_cast<moho::SofdecSfdWorkctrlSubobj*>(SjAddressToPointer(workctrlAddress));
    if (sftrn_BuildAll(workctrlSubobj, transferBuildConfigWords) != 0) {
      return SFLIB_SetErr(workctrlAddress, kSftrnErrBuildFailed);
    }
    return 0;
  }

  /**
   * Address: 0x00ADF8D0 (FUN_00ADF8D0, _sftrn_InitTrData)
   */
  std::int32_t* sftrn_InitTrData(std::int32_t* const transferDataWords, const std::int32_t transferDescriptorAddress)
  {
    auto* const transferLane = reinterpret_cast<SftrnTransferDataLaneView*>(transferDataWords);
    transferLane->termFlag = 0;
    transferLane->prepFlag = 0;
    transferLane->transferDescriptorAddress = transferDescriptorAddress;
    transferLane->sourceLaneIndex = 8;
    transferLane->targetLaneIndex0 = 8;
    transferLane->targetLaneIndex1 = 8;
    transferLane->targetLaneIndex2 = 8;
    transferLane->transferEndState = -1;
    return transferDataWords;
  }

  /**
   * Address: 0x00ADF910 (FUN_00ADF910, _sftrn_BuildAll)
   */
  std::int32_t sftrn_BuildAll(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;

    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    auto* const workctrlState = reinterpret_cast<SftrnWorkctrlStateView*>(workctrlSubobj);

    if (transferBuildConfig->hasSystemLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 0);
      (void)sftrn_BuildSystem(workctrlSubobj, transferBuildConfigWords);
      return 0;
    }
    if (transferBuildConfig->hasAudioLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 1);
      (void)sftrn_BuildAudio(workctrlSubobj, transferBuildConfigWords);
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      workctrlState->videoConditionState = 0;
      return 0;
    }
    if (transferBuildConfig->hasVideoLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 2);
      (void)sftrn_BuildVideo(workctrlSubobj, transferBuildConfigWords);
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
      return 0;
    }
    if (transferBuildConfig->hasUserLane != 0) {
      (void)sftrn_ConnTrnBuf0(workctrlSubobj, 0, 7);
      (void)sftrn_BuildUsr(workctrlSubobj);
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
      workctrlState->videoConditionState = 0;
      return 0;
    }
    return -1;
  }

  /**
   * Address: 0x00ADF9F0 (FUN_00ADF9F0, _sftrn_BuildSystem)
   */
  std::int32_t sftrn_BuildSystem(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;

    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    auto* const workctrlState = reinterpret_cast<SftrnWorkctrlStateView*>(workctrlSubobj);

    (void)sftrn_ConnBufTrn(workctrlSubobj, 0, 1);
    if (transferBuildConfig->hasAudioLane != 0) {
      (void)sftrn_ConnTrnBufV(workctrlSubobj, 1, 1);
      (void)sftrn_BuildAudio(workctrlSubobj, transferBuildConfigWords);
    } else {
      SFSET_SetCond(workctrlSubobj, kSfsetAudioCondition, 0);
      workctrlState->audioConditionState = 0;
    }

    if (transferBuildConfig->hasVideoLane != 0) {
      (void)sftrn_ConnTrnBufA(workctrlSubobj, 1, 2);
      (void)sftrn_BuildVideo(workctrlSubobj, transferBuildConfigWords);
    } else {
      SFSET_SetCond(workctrlSubobj, kSfsetVideoCondition, 0);
      workctrlState->videoConditionState = 0;
    }

    const std::int32_t hasUserLane = transferBuildConfig->hasUserLane;
    if (hasUserLane != 0) {
      (void)sftrn_ConnTrnBufU(workctrlSubobj, 1, 7);
      return sftrn_BuildUsr(workctrlSubobj);
    }
    return hasUserLane;
  }

  /**
   * Address: 0x00ADFA90 (FUN_00ADFA90, _sftrn_BuildAudio)
   */
  std::int32_t sftrn_BuildAudio(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    (void)sftrn_ConnBufTrn(workctrlSubobj, 1, 2);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 2, 3);
    if (transferBuildConfig->hasAudioExtendedLane == 0) {
      return sftrn_ConnBufTrn(workctrlSubobj, 3, 6);
    }
    (void)sftrn_ConnBufTrn(workctrlSubobj, 3, 4);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 4, 5);
    return sftrn_ConnBufTrn(workctrlSubobj, 5, 6);
  }

  /**
   * Address: 0x00ADFAF0 (FUN_00ADFAF0, _sftrn_BuildVideo)
   */
  std::int32_t sftrn_BuildVideo(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t* const transferBuildConfigWords
  )
  {
    const auto* const transferBuildConfig = reinterpret_cast<const SftrnBuildConfigView*>(transferBuildConfigWords);
    (void)sftrn_ConnBufTrn(workctrlSubobj, 2, 3);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 3, 4);
    if (transferBuildConfig->hasVideoExtendedLane == 0) {
      return sftrn_ConnBufTrn(workctrlSubobj, 4, 7);
    }
    (void)sftrn_ConnBufTrn(workctrlSubobj, 4, 5);
    (void)sftrn_ConnTrnBuf0(workctrlSubobj, 5, 6);
    return sftrn_ConnBufTrn(workctrlSubobj, 6, 7);
  }

  /**
   * Address: 0x00ADFB50 (FUN_00ADFB50, _sftrn_BuildUsr)
   */
  std::int32_t sftrn_BuildUsr(moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj)
  {
    return sftrn_ConnBufTrn(workctrlSubobj, 7, 8);
  }

  /**
   * Address: 0x00AD88A0 (FUN_00AD88A0, _sfset_IsCondValid)
   *
   * What it does:
   * Validates condition updates that require transfer-lane setup and returns
   * non-zero when the condition write is allowed.
   */
  std::int32_t sfset_IsCondValid(
    moho::SofdecSfdWorkctrlSubobj* const workctrlSubobj,
    const std::int32_t conditionId,
    const std::int32_t value
  )
  {
    constexpr std::int32_t kSfsetAudioCondition = 5;
    constexpr std::int32_t kSfsetVideoCondition = 6;
    constexpr std::int32_t kSfsetConditionEnabled = 1;

    if (conditionId == kSfsetVideoCondition && value == kSfsetConditionEnabled) {
      return SFTRN_IsSetup(workctrlSubobj, 3) != 0 ? 1 : 0;
    }
    if (conditionId == kSfsetAudioCondition && value == kSfsetConditionEnabled) {
      return SFTRN_IsSetup(workctrlSubobj, 2) != 0 ? 1 : 0;
    }
    return 1;
  }

