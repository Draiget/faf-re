  /**
   * Address: 0x00B0A320 (FUN_00B0A320, _ADXT_GetVersion)
   *
   * What it does:
   * Returns static ADXT build/version banner text.
   */
  const char* ADXT_GetVersion();
  /**
   * Address: 0x00B0A330 (FUN_00B0A330, _ADXT_ConfigVsyncSvr)
   *
   * What it does:
   * Stores ADXT vsync-server enable lane and returns stored value.
   */
  std::int32_t ADXT_ConfigVsyncSvr(std::int32_t enableVsyncServer);
  /**
   * Address: 0x00B0A340 (FUN_00B0A340, _adxini_rnaerr_cbfn)
   *
   * What it does:
   * Bridges ADXRNA error callback text into ADXERR reporter lane.
   */
  void adxini_rnaerr_cbfn(std::int32_t errorObject, const char* message);
  /**
   * Address: 0x00B0A360 (FUN_00B0A360, _ADXT_VsyncProc)
   *
   * What it does:
   * Increments global ADXT vsync counter and runs one ADXT server tick.
   */
  void ADXT_VsyncProc();
  /**
   * Address: 0x00B0A370 (FUN_00B0A370, _adxt_exec_tsvr)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT decode-server tick.
   */
  std::int32_t adxt_exec_tsvr();
  /**
   * Address: 0x00B0A380 (FUN_00B0A380, _adxt_exec_fssvr)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT filesystem-server tick.
   */
  std::int32_t adxt_exec_fssvr();
  /**
   * Address: 0x00B0A480 (FUN_00B0A480, _adxt_exec_main_thrd)
   *
   * What it does:
   * SVM callback thunk that runs one ADXT seamless-LSC server tick.
   */
  std::int32_t adxt_exec_main_thrd();
  void adxt_ExecLscSvr();
  /**
   * Address: 0x00B0A490 (FUN_00B0A490, _ADXT_ResetLibrary)
   *
   * What it does:
   * Resets ADXT init-reference lane and reruns ADXT global initialization.
   */
  void ADXT_ResetLibrary();
  /**
   * Address: 0x00B0E2B0 (FUN_00B0E2B0, _adxt_ExecServer)
   *
   * What it does:
   * Runs one ADXT decode-server tick with reentrancy guard and dispatches SJD,
   * per-runtime handle ticks, then RNA server.
  */
  void adxt_ExecServer();
  /**
   * Address: 0x00B18B70 (FUN_00B18B70, _ADXSJD_ExecServer)
   */
  void ADXSJD_ExecServer();
  extern std::int32_t adxt_tsvr_enter_cnt;
  void ADXT_ExecHndl(void* adxtRuntime);
  void adxt_ExecHndl(void* adxtRuntime);
  void ADXT_ExecRdErrChk(void* adxtRuntime);
  std::int32_t ADXT_ExecRdCompChk(void* adxtRuntime);
  std::int32_t ADXT_GetStat(void* adxtRuntime);
  std::int32_t adxt_GetStat(void* adxtRuntime);
  /**
   * Address: 0x00B0D3C0 (FUN_00B0D3C0, _ADXT_SetTimeMode)
   *
   * What it does:
   * Updates ADXT global time-mode lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTimeMode(std::int32_t timeMode);
  /**
   * Address: 0x00B0D3E0 (FUN_00B0D3E0, _adxt_SetTimeMode)
   *
   * What it does:
   * Stores ADXT global time-mode lane and updates time-to-vsync presets.
   */
  std::int32_t adxt_SetTimeMode(std::int32_t timeMode);
  std::int32_t ADXT_GetNumChan(void* adxtRuntime);
  std::int32_t adxt_GetNumChan(void* adxtRuntime);
  /**
   * Address: 0x00B0D7E0 (FUN_00B0D7E0, _ADXT_GetTimeReal)
   *
   * What it does:
   * Returns ADXT playback time percentage under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetTimeReal(void* adxtRuntime);
  /**
   * Address: 0x00B0D800 (FUN_00B0D800, _adxt_GetTimeReal)
   *
   * What it does:
   * Returns ADXT playback time percentage from current time units/scale.
   */
  std::int32_t adxt_GetTimeReal(void* adxtRuntime);
  /**
   * Address: 0x00B0D830 (FUN_00B0D830, _ADXT_GetNumSmpl)
   *
   * What it does:
   * Returns ADXT total sample count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetNumSmpl(void* adxtRuntime);
  /**
   * Address: 0x00B0D850 (FUN_00B0D850, _adxt_GetNumSmpl)
   *
   * What it does:
   * Returns ADXT total sample count when decode state is active.
   */
  std::int32_t adxt_GetNumSmpl(void* adxtRuntime);
  /**
   * Address: 0x00B0D880 (FUN_00B0D880, _ADXT_GetSfreq)
   *
   * What it does:
   * Returns ADXT sample-rate lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetSfreq(void* adxtRuntime);
  /**
   * Address: 0x00B0D8A0 (FUN_00B0D8A0, _adxt_GetSfreq)
   *
   * What it does:
   * Returns ADXT sample-rate lane when decode state is active.
   */
  std::int32_t adxt_GetSfreq(void* adxtRuntime);
  /**
   * Address: 0x00B0D920 (FUN_00B0D920, _ADXT_GetHdrLen)
   *
   * What it does:
   * Returns ADXT header-length lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetHdrLen(void* adxtRuntime);
  /**
   * Address: 0x00B0D940 (FUN_00B0D940, _adxt_GetHdrLen)
   *
   * What it does:
   * Returns ADXT stream-header length when decode state is active.
   */
  std::int32_t adxt_GetHdrLen(void* adxtRuntime);
  /**
   * Address: 0x00B0D970 (FUN_00B0D970, _ADXT_GetFmtBps)
   *
   * What it does:
   * Returns ADXT format bit-depth under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetFmtBps(void* adxtRuntime);
  /**
   * Address: 0x00B0D990 (FUN_00B0D990, _adxt_GetFmtBps)
   *
   * What it does:
   * Returns ADXT format bit-depth when decode state is active.
   */
  std::int32_t adxt_GetFmtBps(void* adxtRuntime);
  /**
   * Address: 0x00B0EE70 (FUN_00B0EE70, _ADXT_SetKeyString)
   *
   * What it does:
   * Applies ADXT key-string lane update under ADXCRS enter/leave guards.
   */
  void ADXT_SetKeyString(void* adxtRuntime, const char* extString);
  /**
   * Address: 0x00B0EE90 (FUN_00B0EE90, _adxt_SetKeyString)
   *
   * What it does:
   * Forwards ADXT key-string lane to owning ADXSJD handle or reports null runtime.
   */
  void adxt_SetKeyString(void* adxtRuntime, const char* extString);
  /**
   * Address: 0x00B0EEC0 (FUN_00B0EEC0, _ADXT_SetDefKeyString)
   *
   * What it does:
   * Applies global ADXT default-key-string update under ADXCRS enter/leave
   * guards.
   */
  void ADXT_SetDefKeyString(const char* extString);
  /**
   * Address: 0x00B0EEE0 (FUN_00B0EEE0, _adxt_SetDefKeyString)
   *
   * What it does:
   * Forwards one default key string lane to ADXSJD global key-string store.
   */
  std::int32_t adxt_SetDefKeyString(const char* extString);
  /**
   * Address: 0x00B0EEF0 (FUN_00B0EEF0, _ADXT_GetRna)
   *
   * What it does:
   * Returns ADXT RNA handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetRna(void* adxtRuntime);
  /**
   * Address: 0x00B0EF10 (FUN_00B0EF10, _adxt_GetRna)
   *
   * What it does:
   * Returns ADXT RNA handle lane at offset `+0x0C`.
   */
  std::int32_t adxt_GetRna(void* adxtRuntime);
  /**
   * Address: 0x00B0EF20 (FUN_00B0EF20, _ADXT_SetDefFmt)
   *
   * What it does:
   * Applies ADXT default-format lane update under ADXCRS enter/leave guards.
   */
  void ADXT_SetDefFmt(void* adxtRuntime, std::int32_t requestedFormat);
  /**
   * Address: 0x00B0EF40 (FUN_00B0EF40, _adxt_SetDefFmt)
   *
   * What it does:
   * Forwards requested default format to ADXSJD for the owning ADXT SJD handle.
   */
  std::int32_t adxt_SetDefFmt(void* adxtRuntime, std::int32_t requestedFormat);
  /**
   * Address: 0x00B0E830 (FUN_00B0E830, _ADXT_GetStm)
   *
   * What it does:
   * Returns ADXT stream handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStm(void* adxtRuntime);
  /**
   * Address: 0x00B0E850 (FUN_00B0E850, _adxt_GetStm)
   *
   * What it does:
   * Returns ADXT runtime stream handle lane.
   */
  std::int32_t adxt_GetStm(void* adxtRuntime);
  /**
   * Address: 0x00B0E860 (FUN_00B0E860, _ADXT_TermSupply)
   *
   * What it does:
   * Runs ADXT terminate-supply request under ADXCRS enter/leave guards.
   */
  void ADXT_TermSupply(void* adxtRuntime);
  /**
   * Address: 0x00B0E880 (FUN_00B0E880, _adxt_TermSupply)
   *
   * What it does:
   * Forwards ADXT terminate-supply request to ADXSJD runtime.
   */
  std::int32_t adxt_TermSupply(void* adxtRuntime);
  /**
   * Address: 0x00B0E890 (FUN_00B0E890, _ADXT_SetDrctLvl)
   *
   * What it does:
   * Legacy direct-level setter stub lane.
   */
  void ADXT_SetDrctLvl();
  /**
   * Address: 0x00B0E8A0 (FUN_00B0E8A0, _ADXT_GetDrctLvl)
   *
   * What it does:
   * Legacy direct-level getter stub lane; always returns zero.
   */
  std::int32_t ADXT_GetDrctLvl();
  /**
   * Address: 0x00B0E8B0 (FUN_00B0E8B0, _ADXT_SetFx)
   *
   * What it does:
   * Legacy effect setter stub lane.
   */
  void ADXT_SetFx();
  /**
   * Address: 0x00B0E8C0 (FUN_00B0E8C0, _ADXT_GetFx)
   *
   * What it does:
   * Legacy effect getter stub lane.
   */
  void ADXT_GetFx();
  /**
   * Address: 0x00B0E8D0 (FUN_00B0E8D0, _ADXT_SetFilter)
   *
   * What it does:
   * Legacy filter setter stub lane.
   */
  void ADXT_SetFilter();
  /**
   * Address: 0x00B0E8E0 (FUN_00B0E8E0, _ADXT_GetFilter)
   *
   * What it does:
   * Legacy filter getter stub lane.
   */
  void ADXT_GetFilter();
  /**
   * Address: 0x00B0E220 (FUN_00B0E220, _ADXT_SetAutoRcvr)
   *
   * What it does:
   * Stores ADXT auto-recover mode lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetAutoRcvr(void* adxtRuntime, std::int32_t autoRecoverEnabled);
  /**
   * Address: 0x00B0E240 (FUN_00B0E240, _adxt_SetAutoRcvr)
   *
   * What it does:
   * Stores ADXT auto-recover mode byte (`+0x6D`).
   */
  std::int32_t adxt_SetAutoRcvr(void* adxtRuntime, std::int32_t autoRecoverEnabled);
  /**
   * Address: 0x00B0E250 (FUN_00B0E250, _ADXT_IsCompleted)
   *
   * What it does:
   * Returns ADXT completed-state lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_IsCompleted(void* adxtRuntime);
  /**
   * Address: 0x00B0E270 (FUN_00B0E270, _adxt_IsCompleted)
   *
   * What it does:
   * Returns whether ADXT runtime state byte (`+0x01`) equals terminal state `5`;
   * reports null-runtime parameter error and returns `-1` otherwise.
   */
  std::int32_t adxt_IsCompleted(void* adxtRuntime);
  /**
   * Address: 0x00B0DD30 (FUN_00B0DD30, _ADXT_GetDataId)
   *
   * What it does:
   * Returns ADXT data-id pointer under ADXCRS enter/leave guards.
   */
  std::uint8_t* ADXT_GetDataId(void* adxtRuntime);
  /**
   * Address: 0x00B0DD50 (FUN_00B0DD50, _adxt_GetDataId)
   *
   * What it does:
   * Returns ADXT SJD data-id pointer lane.
   */
  std::uint8_t* adxt_GetDataId(void* adxtRuntime);
  /**
   * Address: 0x00B0DD60 (FUN_00B0DD60, _ADXT_GetDataIdFromMem)
   *
   * What it does:
   * Decodes AINF data-id from ADX header bytes under ADXCRS guards.
   */
  std::uint8_t* ADXT_GetDataIdFromMem(const std::uint8_t* sourceBytes);
  /**
   * Address: 0x00B0DD80 (FUN_00B0DD80, _adxt_GetDataIdFromMem)
   *
   * What it does:
   * Decodes AINF data-id from ADX header bytes into shared ADXT scratch buffer.
   */
  std::uint8_t* adxt_GetDataIdFromMem(const std::uint8_t* sourceBytes);
  /**
   * Address: 0x00B0DDC0 (FUN_00B0DDC0, _ADXT_SetAinfSw)
   *
   * What it does:
   * Stores ADXT AINF-switch state under ADXCRS enter/leave guards.
   */
  void ADXT_SetAinfSw(void* adxtRuntime, std::int32_t enabled);
  /**
   * Address: 0x00B0DBA0 (FUN_00B0DBA0, _ADXT_GetOutBalance)
   *
   * What it does:
   * Returns ADXT output-balance lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetOutBalance(void* adxtRuntime);
  /**
   * Address: 0x00B0DBC0 (FUN_00B0DBC0, _adxt_GetOutBalance)
   *
   * What it does:
   * Returns ADXT output-balance lane (`+0x46`) or reports parameter error.
   */
  std::int32_t adxt_GetOutBalance(void* adxtRuntime);
  /**
   * Address: 0x00B0DBE0 (FUN_00B0DBE0, _ADXT_SetOutVol)
   *
   * What it does:
   * Stores ADXT output-volume lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetOutVol(void* adxtRuntime, std::int16_t volumeLevel);
  /**
   * Address: 0x00B0DC00 (FUN_00B0DC00, _adxt_SetOutVol)
   *
   * What it does:
   * Stores ADXT output-volume lane (`+0x40`) and applies effective RNA output
   * volume.
   */
  void adxt_SetOutVol(void* adxtRuntime, std::int16_t volumeLevel);
  /**
   * Address: 0x00B0DC60 (FUN_00B0DC60, _ADXT_GetOutVol)
   *
   * What it does:
   * Returns ADXT output-volume lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetOutVol(void* adxtRuntime);
  /**
   * Address: 0x00B0DC80 (FUN_00B0DC80, _adxt_GetOutVol)
   *
   * What it does:
   * Returns ADXT output-volume lane (`+0x40`) or reports parameter error.
   */
  std::int32_t adxt_GetOutVol(void* adxtRuntime);
  /**
   * Address: 0x00B0DCA0 (FUN_00B0DCA0, _ADXT_GetDefOutVol)
   *
   * What it does:
   * Returns ADXT default output-volume lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDefOutVol(void* adxtRuntime);
  /**
   * Address: 0x00B0DCC0 (FUN_00B0DCC0, _adxt_GetDefOutVol)
   *
   * What it does:
   * Returns ADXSJD default output-volume lane for one ADXT runtime.
   */
  std::int32_t adxt_GetDefOutVol(void* adxtRuntime);
  /**
   * Address: 0x00B0DCE0 (FUN_00B0DCE0, _ADXT_GetDefOutPan)
   *
   * What it does:
   * Returns ADXT default per-lane pan under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDefOutPan(void* adxtRuntime, std::int32_t laneIndex);
  /**
   * Address: 0x00B0DD10 (FUN_00B0DD10, _adxt_GetDefOutPan)
   *
   * What it does:
   * Returns ADXSJD default per-lane pan for one ADXT runtime.
   */
  std::int32_t adxt_GetDefOutPan(void* adxtRuntime, std::int32_t laneIndex);
  /**
   * Address: 0x00B0DDE0 (FUN_00B0DDE0, _ADXT_GetAinfSw)
   *
   * What it does:
   * Returns ADXT AINF-switch lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetAinfSw(void* adxtRuntime);
  /**
   * Address: 0x00B0DE00 (FUN_00B0DE00, _adxt_SetAinfSw)
   *
   * What it does:
   * Stores ADXT AINF-switch byte lane (`+0xA9`).
   */
  std::int8_t adxt_SetAinfSw(void* adxtRuntime, std::int8_t enabled);
  /**
   * Address: 0x00B0DE10 (FUN_00B0DE10, _adxt_GetAinfSw)
   *
   * What it does:
   * Returns ADXT AINF-switch byte lane (`+0xA9`).
   */
  std::int32_t adxt_GetAinfSw(void* adxtRuntime);
  /**
   * Address: 0x00B0DE20 (FUN_00B0DE20, _ADXT_SetDefSvrFreq)
   *
   * What it does:
   * Stores global ADXT default server-frequency lane under ADXCRS guards.
   */
  void ADXT_SetDefSvrFreq(std::int32_t serverFrequency);
  /**
   * Address: 0x00B0DE40 (FUN_00B0DE40, _adxt_SetDefSvrFreq)
   *
   * What it does:
   * Stores global ADXT default/last server-frequency lanes and returns value.
   */
  std::int32_t adxt_SetDefSvrFreq(std::int32_t serverFrequency);
  /**
   * Address: 0x00B0DE50 (FUN_00B0DE50, _ADXT_SetSvrFreq)
   *
   * What it does:
   * Stores ADXT runtime server-frequency lane under ADXCRS guards.
   */
  void ADXT_SetSvrFreq(void* adxtRuntime, std::int32_t serverFrequency);
  /**
   * Address: 0x00B0DE70 (FUN_00B0DE70, _adxt_SetSvrFreq)
   *
   * What it does:
   * Stores ADXT runtime server-frequency lane (`+0x38`) and global last value.
   */
  void adxt_SetSvrFreq(void* adxtRuntime, std::int32_t serverFrequency);
  /**
   * Address: 0x00B0DEA0 (FUN_00B0DEA0, _ADXT_SetReloadTime)
   *
   * What it does:
   * Stores ADXT reload-time-derived sector lane under ADXCRS guards.
   */
  void ADXT_SetReloadTime(void* adxtRuntime, float reloadSeconds, std::int32_t channelCount, std::int32_t sampleRate);
  /**
   * Address: 0x00B0DED0 (FUN_00B0DED0, _adxt_SetReloadTime)
   *
   * What it does:
   * Converts reload time to sector budget and updates ADXSTM buffer sizing.
   */
  void adxt_SetReloadTime(void* adxtRuntime, float reloadSeconds, std::int32_t channelCount, std::int32_t sampleRate);
  /**
   * Address: 0x00B0DF40 (FUN_00B0DF40, _ADXT_ResetReloadTime)
   *
   * What it does:
   * Runs ADXT reload-time reset lane under ADXCRS enter/leave guards.
   */
  void ADXT_ResetReloadTime(void* adxtRuntime);
  /**
   * Address: 0x00B0DF60 (FUN_00B0DF60, _adxt_ResetReloadTime)
   *
   * What it does:
   * Recomputes ADXT seamless reload sector hint from stream-buffer sector limit.
   */
  void adxt_ResetReloadTime(void* adxtRuntime);
  /**
   * Address: 0x00B0DFC0 (FUN_00B0DFC0, _ADXT_SetReloadSct)
   *
   * What it does:
   * Stores ADXT reload-sector count under ADXCRS enter/leave guards.
   */
  void ADXT_SetReloadSct(void* adxtRuntime, std::int32_t reloadSectorCount);
  /**
   * Address: 0x00B0DFE0 (FUN_00B0DFE0, _adxt_SetReloadSct)
   *
   * What it does:
   * Stores ADXT reload-sector hint and updates stream buffer sizing if active.
   */
  void adxt_SetReloadSct(void* adxtRuntime, std::int16_t reloadSectorCount);
  /**
   * Address: 0x00B0E020 (FUN_00B0E020, _ADXT_GetReloadSct)
   *
   * What it does:
   * Returns ADXT reload-sector hint lane (`+0x3E`).
   */
  std::int32_t ADXT_GetReloadSct(void* adxtRuntime);
  /**
   * Address: 0x00B0E030 (FUN_00B0E030, _ADXT_GetNumSctIbuf)
   *
   * What it does:
   * Returns ADXT input-buffer queued sector count under ADXCRS guards.
   */
  std::int32_t ADXT_GetNumSctIbuf(void* adxtRuntime);
  /**
   * Address: 0x00B0E050 (FUN_00B0E050, _adxt_GetNumSctIbuf)
   *
   * What it does:
   * Returns ADXT input-buffer queued sector count or reports parameter error.
   */
  std::int32_t adxt_GetNumSctIbuf(void* adxtRuntime);
  /**
   * Address: 0x00B0E090 (FUN_00B0E090, _ADXT_GetNumSmplObuf)
   *
   * What it does:
   * Returns ADXT output-buffer sample count for one lane under ADXCRS guards.
   */
  std::int32_t ADXT_GetNumSmplObuf(void* adxtRuntime, std::int32_t lane);
  /**
   * Address: 0x00B0E0C0 (FUN_00B0E0C0, _adxt_GetNumSmplObuf)
   *
   * What it does:
   * Returns ADXT output-buffer sample count for one lane or reports parameter
   * error.
   */
  std::int32_t adxt_GetNumSmplObuf(void* adxtRuntime, std::int32_t lane);
  /**
   * Address: 0x00B0E100 (FUN_00B0E100, _ADXT_GetIbufRemainTime)
   *
   * What it does:
   * Returns ADXT input-buffer remaining playback time under ADXCRS guards.
   */
  double ADXT_GetIbufRemainTime(void* adxtRuntime);
  /**
   * Address: 0x00B0E120 (FUN_00B0E120, _adxt_GetIbufRemainTime)
   *
   * What it does:
   * Returns ADXT input-buffer remaining playback time in seconds.
   */
  double adxt_GetIbufRemainTime(void* adxtRuntime);
  /**
   * Address: 0x00B0E1B0 (FUN_00B0E1B0, _ADXT_IsIbufSafety)
   *
   * What it does:
   * Returns whether ADXT input buffer is above safety threshold under ADXCRS
   * guards.
   */
  std::int32_t ADXT_IsIbufSafety(void* adxtRuntime);
  /**
   * Address: 0x00B0E1D0 (FUN_00B0E1D0, _adxt_IsIbufSafety)
   *
   * What it does:
   * Returns whether ADXT input buffer is above safety threshold.
   */
  std::int32_t adxt_IsIbufSafety(void* adxtRuntime);
  /**
   * Address: 0x00B0E320 (FUN_00B0E320, _ADXT_ExecDecServer)
   *
   * What it does:
   * Runs ADXT decode-server execution lane under ADXCRS enter/leave guards.
   */
  void ADXT_ExecDecServer();
  /**
   * Address: 0x00B0E330 (FUN_00B0E330, _adxt_ExecDecServer)
   *
   * What it does:
   * Legacy decode-server thunk that forwards to `adxt_ExecServer`.
   */
  void adxt_ExecDecServer();
  /**
   * Address: 0x00B0E340 (FUN_00B0E340, _ADXT_GetErrCode)
   *
   * What it does:
   * Returns ADXT error code lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetErrCode(void* adxtRuntime);
  /**
   * Address: 0x00B0E360 (FUN_00B0E360, _adxt_GetErrCode)
   *
   * What it does:
   * Returns ADXT runtime error code lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetErrCode(void* adxtRuntime);
  /**
   * Address: 0x00B0E3A0 (FUN_00B0E3A0, _adxt_ClearErrCode)
   *
   * What it does:
   * Clears ADXT runtime decode/error tracking lanes or reports null-runtime
   * parameter error.
   */
  void adxt_ClearErrCode(void* adxtRuntime);
  /**
   * Address: 0x00B0E380 (FUN_00B0E380, _ADXT_ClearErrCode)
   *
   * What it does:
   * Clears ADXT error state lanes under ADXCRS enter/leave guards.
   */
  void ADXT_ClearErrCode(void* adxtRuntime);
  /**
   * Address: 0x00B0E3F0 (FUN_00B0E3F0, _adxt_GetLpCnt)
   *
   * What it does:
   * Returns ADXT runtime loop-count lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetLpCnt(void* adxtRuntime);
  /**
   * Address: 0x00B0E3D0 (FUN_00B0E3D0, _ADXT_GetLpCnt)
   *
   * What it does:
   * Returns ADXT loop-count lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetLpCnt(void* adxtRuntime);
  /**
   * Address: 0x00B0E430 (FUN_00B0E430, _adxt_SetLpFlg)
   *
   * What it does:
   * Updates ADXT seamless-loop flag and aligned loop decode-window lane.
   */
  void adxt_SetLpFlg(void* adxtRuntime, std::int32_t enabled);
  /**
   * Address: 0x00B0E410 (FUN_00B0E410, _ADXT_SetLpFlg)
   *
   * What it does:
   * Updates ADXT seamless-loop flag under ADXCRS enter/leave guards.
   */
  void ADXT_SetLpFlg(void* adxtRuntime, std::int32_t enabled);
  /**
   * Address: 0x00B0E4F0 (FUN_00B0E4F0, _ADXT_GetInputSj)
   *
   * What it does:
   * Returns ADXT input-SJ handle lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetInputSj(void* adxtRuntime);
  /**
   * Address: 0x00B0E510 (FUN_00B0E510, _adxt_GetInputSj)
   *
   * What it does:
   * Returns ADXT runtime input-SJ handle lane or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetInputSj(void* adxtRuntime);
  /**
   * Address: 0x00B0E530 (FUN_00B0E530, _ADXT_SetWaitPlayStart)
   *
   * What it does:
   * Stores ADXT wait-play-start lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetWaitPlayStart(void* adxtRuntime, std::int32_t waitEnabled);
  /**
   * Address: 0x00B0E550 (FUN_00B0E550, _adxt_SetWaitPlayStart)
   *
   * What it does:
   * Stores ADXT wait-play-start flag byte (`+0x70`) or reports null-runtime
   * parameter error.
   */
  void adxt_SetWaitPlayStart(void* adxtRuntime, std::int32_t waitEnabled);
  /**
   * Address: 0x00B0E570 (FUN_00B0E570, _ADXT_IsReadyPlayStart)
   *
   * What it does:
   * Returns ADXT ready-play-start lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_IsReadyPlayStart(void* adxtRuntime);
  /**
   * Address: 0x00B0E590 (FUN_00B0E590, _adxt_IsReadyPlayStart)
   *
   * What it does:
   * Returns ADXT ready-play-start flag byte (`+0x71`) or `-1` on null runtime.
   */
  std::int32_t adxt_IsReadyPlayStart(void* adxtRuntime);
  /**
   * Address: 0x00B0E5B0 (FUN_00B0E5B0, _ADXT_Pause)
   *
   * What it does:
   * Runs ADXT pause lane under ADXCRS enter/leave guards.
   */
  void ADXT_Pause(void* adxtRuntime, std::int32_t pauseEnabled);
  void adxt_Pause(void* adxtRuntime, std::int32_t pauseEnabled);
  /**
   * Address: 0x00B0E690 (FUN_00B0E690, _ADXT_GetStatPause)
   *
   * What it does:
   * Returns ADXT pause-state lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStatPause(void* adxtRuntime);
  /**
   * Address: 0x00B0E6B0 (FUN_00B0E6B0, _adxt_GetStatPause)
   *
   * What it does:
   * Returns ADXT pause-state byte (`+0x72`) or reports null-runtime parameter
   * error.
   */
  std::int32_t adxt_GetStatPause(void* adxtRuntime);
  /**
   * Address: 0x00B0E6D0 (FUN_00B0E6D0, _ADXT_PauseAll)
   *
   * What it does:
   * Applies global ADXT pause-all state under ADXCRS enter/leave guards.
   */
  void ADXT_PauseAll(std::int32_t pauseAllEnabled);
  /**
   * Address: 0x00B0E6F0 (FUN_00B0E6F0, _adxt_PauseAll)
   *
   * What it does:
   * Forwards global ADXT pause-all state to ADXRNA pause-all runtime lanes.
   */
  std::int32_t adxt_PauseAll(std::int32_t pauseAllEnabled);
  /**
   * Address: 0x00B0E700 (FUN_00B0E700, _ADXT_GetStatPauseAll)
   *
   * What it does:
   * Returns global ADXT pause-all state under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetStatPauseAll();
  /**
   * Address: 0x00B0E720 (FUN_00B0E720, _adxt_GetStatPauseAll)
   *
   * What it does:
   * Returns current ADXRNA pause-all state for ADXT callers.
   */
  std::int32_t adxt_GetStatPauseAll();
  /**
   * Address: 0x00B0E730 (FUN_00B0E730, _ADXT_SetTranspose)
   *
   * What it does:
   * Runs ADXT transpose update lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTranspose(void* adxtRuntime, std::int32_t transposeOctaves, std::int32_t transposeCents);
  /**
   * Address: 0x00B0E760 (FUN_00B0E760, _adxt_SetTranspose)
   *
   * What it does:
   * Updates ADXT transpose lanes and recomputes decode window/sample budget for
   * active decode state.
   */
  std::int32_t adxt_SetTranspose(void* adxtRuntime, std::int32_t transposeOctaves, std::int32_t transposeCents);
  /**
   * Address: 0x00B0E7F0 (FUN_00B0E7F0, _ADXT_GetTranspose)
   *
   * What it does:
   * Returns ADXT transpose lanes under ADXCRS enter/leave guards.
   */
  void ADXT_GetTranspose(void* adxtRuntime, std::int32_t* outTransposeOctaves, std::int32_t* outTransposeCents);
  /**
   * Address: 0x00B0E820 (FUN_00B0E820, _adxt_GetTranspose)
   *
   * What it does:
   * Returns ADXT transpose lanes from RNA transpose words.
   */
  std::int32_t adxt_GetTranspose(void* adxtRuntime, std::int32_t* outTransposeOctaves, std::int32_t* outTransposeCents);
  /**
   * Address: 0x00B0E8F0 (FUN_00B0E8F0, _ADXT_EntryErrFunc)
   *
   * What it does:
   * Registers ADXT error callback lane through ADXERR callback owner.
   */
  void ADXT_EntryErrFunc(moho::AdxmErrorCallback callbackFunction, std::int32_t callbackObject);
  /**
   * Address: 0x00B0E900 (FUN_00B0E900, _ADXT_DiscardSmpl)
   *
   * What it does:
   * Runs ADXT discard-sample lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_DiscardSmpl(void* adxtRuntime, std::int32_t sampleCount);
  /**
   * Address: 0x00B0E930 (FUN_00B0E930, _adxt_DiscardSmpl)
   *
   * What it does:
   * Discards ADXT samples, executes server tick, and refreshes playback time anchor lanes.
   */
  std::int32_t adxt_DiscardSmpl(void* adxtRuntime, std::int32_t sampleCount);
  /**
   * Address: 0x00B0E9B0 (FUN_00B0E9B0, _ADXT_GetTimeOfst)
   *
   * What it does:
   * Returns ADXT time-offset lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetTimeOfst(void* adxtRuntime);
  /**
   * Address: 0x00B0E9D0 (FUN_00B0E9D0, _adxt_GetTimeOfst)
   *
   * What it does:
   * Returns ADXT runtime time-offset lane.
   */
  std::int32_t adxt_GetTimeOfst(void* adxtRuntime);
  /**
   * Address: 0x00B0E9E0 (FUN_00B0E9E0, _ADXT_SetTimeOfst)
   *
   * What it does:
   * Stores ADXT time-offset lane under ADXCRS enter/leave guards.
   */
  void ADXT_SetTimeOfst(void* adxtRuntime, std::int32_t timeOffset);
  /**
   * Address: 0x00B0EA00 (FUN_00B0EA00, _adxt_SetTimeOfst)
   *
   * What it does:
   * Stores ADXT runtime time-offset lane and returns the stored value.
   */
  std::int32_t adxt_SetTimeOfst(void* adxtRuntime, std::int32_t timeOffset);
  /**
   * Address: 0x00B0EA10 (FUN_00B0EA10, _ADXT_AdjustSmpl)
   *
   * What it does:
   * Runs ADXT sample-adjust lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_AdjustSmpl(void* adxtRuntime, std::int32_t sampleDelta);
  /**
   * Address: 0x00B0EA40 (FUN_00B0EA40, _adxt_AdjustSmpl)
   *
   * What it does:
   * Forwards one ADXT sample-adjust request into ADXSJD adjust lane.
   */
  std::int32_t adxt_AdjustSmpl(void* adxtRuntime, std::int32_t sampleDelta);
  /**
   * Address: 0x00B0EAA0 (FUN_00B0EAA0, _ADXT_EntryFltFunc)
   *
   * What it does:
   * Runs ADXT filter-entry query lane under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_EntryFltFunc(void* adxtRuntime);
  /**
   * Address: 0x00B0EAC0 (FUN_00B0EAC0, _adxt_EntryFltFunc)
   *
   * What it does:
   * Returns ADXT link-switch request byte as signed lane value.
   */
  std::int32_t adxt_EntryFltFunc(void* adxtRuntime);
  /**
   * Address: 0x00B0D440 (FUN_00B0D440, _adxt_GetTimeSfreq)
   *
   * What it does:
   * Returns ADXT playback time units/frequency pair from RNA/SJD lanes.
   */
  std::int32_t adxt_GetTimeSfreq(void* adxtRuntime, std::int32_t* outTimeUnits, std::int32_t* outTimeScale);
  /**
   * Address: 0x00B0D4F0 (FUN_00B0D4F0, _ADXT_GetTimeSfreq2)
   *
   * What it does:
   * Runs secondary ADXT playback time units/frequency query under ADXCRS
   * guards.
   */
  void ADXT_GetTimeSfreq2(void* adxtRuntime, std::int32_t* outTimeUnits, std::int32_t* outTimeScale);
  /**
   * Address: 0x00B0D520 (FUN_00B0D520, _adxt_GetTimeSfreq2)
   *
   * What it does:
   * Returns ADXT decode-progress-based playback time units/frequency pair.
   */
  std::int32_t adxt_GetTimeSfreq2(void* adxtRuntime, std::int32_t* outTimeUnits, std::int32_t* outTimeScale);
  /**
   * Address: 0x00B0D5F0 (FUN_00B0D5F0)
   *
   * What it does:
   * Increments ADXT auxiliary timing counter lane.
   */
  void ADXT_IncrementAuxTimeCounter();
  /**
   * Address: 0x00B0D600 (FUN_00B0D600, _ADXT_GetTime)
   *
   * What it does:
   * Runs ADXT playback time query under ADXCRS enter/leave guards.
   */
  void ADXT_GetTime(void* adxtRuntime, std::int32_t* outTimeUnits, std::int32_t* outTimeScale);
  /**
   * Address: 0x00B0D630 (FUN_00B0D630, _adxt_GetTime)
   *
   * What it does:
   * Returns ADXT playback time units/frequency pair with time-mode smoothing.
   */
  void adxt_GetTime(void* adxtRuntime, std::int32_t* outTimeUnits, std::int32_t* outTimeScale);
  /**
   * Address: 0x00B0EAD0 (FUN_00B0EAD0, _ADXT_SetCbHdrDec)
   *
   * What it does:
   * Runs ADXT header-filter callback registration under ADXCRS enter/leave guards.
   */
  void ADXT_SetCbHdrDec(void* adxtRuntime, void* filterCallbackAddress, std::int32_t filterCallbackContext);
  /**
   * Address: 0x00B0EB00 (FUN_00B0EB00, _adxt_SetCbHdrDec)
   *
   * What it does:
   * Forwards one ADXT header-filter callback lane into ADXSJD filter registration.
   */
  std::int32_t adxt_SetCbHdrDec(void* adxtRuntime, void* filterCallbackAddress, std::int32_t filterCallbackContext);
  /**
   * Address: 0x00B0EB10 (FUN_00B0EB10, _ADXT_GetDecNumSmpl)
   *
   * What it does:
   * Returns ADXT decoded-sample count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDecNumSmpl(void* adxtRuntime);
  /**
   * Address: 0x00B0EB30 (FUN_00B0EB30, _adxt_GetDecNumSmpl)
   *
   * What it does:
   * Returns decoded-sample count from ADXSJD or reports null-runtime parameter error.
   */
  std::int32_t adxt_GetDecNumSmpl(void* adxtRuntime);
  /**
   * Address: 0x00B0EB60 (FUN_00B0EB60, _ADXT_GetDecDtLen)
   *
   * What it does:
   * Returns ADXT decoded-byte count under ADXCRS enter/leave guards.
   */
  std::int32_t ADXT_GetDecDtLen(void* adxtRuntime);
  /**
   * Address: 0x00B0EB80 (FUN_00B0EB80, _adxt_GetDecDtLen)
   *
   * What it does:
   * Returns decoded-byte count from ADXSJD or reports null-runtime parameter error.
   */
  std::int32_t adxt_GetDecDtLen(void* adxtRuntime);
  /**
   * Address: 0x00B0EBB0 (FUN_00B0EBB0, _ADXT_SetCbDec)
   *
   * What it does:
   * Runs ADXT decode callback registration under ADXCRS enter/leave guards.
   */
  void ADXT_SetCbDec(void* adxtRuntime, void* decodeCallbackAddress, std::int32_t decodeCallbackContext);
  /**
   * Address: 0x00B0EBE0 (FUN_00B0EBE0, _adxt_SetCbDec)
   *
   * What it does:
   * Forwards one ADXT decode callback lane into ADXSJD decode callback registration.
   */
  std::int32_t adxt_SetCbDec(void* adxtRuntime, void* decodeCallbackAddress, std::int32_t decodeCallbackContext);
  /**
   * Address: 0x00B0EC10 (FUN_00B0EC10, _ADXT_IsHeader)
   *
   * What it does:
   * Validates ADX header marker and exports decoded header-identity lane.
   */
  std::int32_t ADXT_IsHeader(const std::uint8_t* sourceBytes, std::int32_t byteCount, std::int32_t* outHeaderIdentity);
  /**
   * Address: 0x00B0EC90 (FUN_00B0EC90, _ADXT_IsEndcode)
   *
   * What it does:
   * Detects ADX end-code marker (`0x8001`) at the start of a byte window and
   * returns consumed-size lane.
   */
  std::int32_t ADXT_IsEndcode(const std::uint8_t* sourceBytes, std::int32_t byteCount, std::int32_t* outConsumedBytes);
  /**
   * Address: 0x00B0ECC0 (FUN_00B0ECC0, _ADXT_InsertSilence)
   *
   * What it does:
   * Inserts zeroed ADX frames into runtime SJ lanes under ADXCRS
   * enter/leave guards.
   */
  std::int32_t ADXT_InsertSilence(void* adxtRuntime, std::int32_t channelCount, std::int32_t sampleCount);
  /**
   * Address: 0x00B0ECF0 (FUN_00B0ECF0, _adxt_InsertSilence)
   *
   * What it does:
   * Emits silent ADX frames into stream-join lane-1 by zero-filling lane-0
   * chunks and submitting split ranges.
   */
  std::int32_t adxt_InsertSilence(void* adxtRuntime, std::int32_t channelCount, std::int32_t sampleCount);
  /**
   * Address: 0x00B0EE10 (FUN_00B0EE10)
   *
   * What it does:
   * Updates global ADXT mono-output mode lane and reapplies pan/balance state
   * across active ADXT runtime slots.
   */
  std::int32_t ADXT_SetOutputMonoMode(std::int32_t enabled);
  std::int32_t ADXT_GetStatRead(void* adxtRuntime);
  std::int32_t adxt_GetStatRead(void* adxtRuntime);
  std::int32_t adxt_eos_entry(void* adxtRuntime);
  std::int32_t adxt_set_outpan(void* adxtRuntime);
  using AdxtEndDecodeInfoCallback =
    std::int32_t(__cdecl*)(std::int32_t adxtRuntime, std::int32_t sampleRate, std::int32_t channelCount, std::int32_t sampleCount);
  AdxtEndDecodeInfoCallback ADXT_SetCbEndDecinfo(AdxtEndDecodeInfoCallback callback);
  void adxt_stat_playend();
  std::int32_t adxt_stat_playing(void* adxtRuntime);
  std::int32_t adxt_stat_decend(void* adxtRuntime);
  void adxt_StartSj(void* adxtRuntime, void* sourceJoinHandle);
  void adxt_ResetEntry(void* adxtRuntime);
  /**
   * Address: 0x00B1ABF0 (FUN_00B1ABF0, _adxt_RcvrReplay)
   *
   * What it does:
   * Recovers one ADXT replay lane after stream/decode errors by stopping active
   * decode transfer, resetting channel lanes, restarting stream read from
   * sector 0, and re-entering SJ decode start.
   */
  void adxt_RcvrReplay(void* adxtRuntime);
  /**
   * Address: 0x00B1ACA0 (FUN_00B1ACA0, _ADXT_ExecErrChk)
   *
   * What it does:
   * Runs one ADXT error-check tick and dispatches configured stop/recover
   * actions for decode, transport, and stream-status fault lanes.
   */
  void ADXT_ExecErrChk(void* adxtRuntime);

  /**
   * Address: 0x00B0D090 (FUN_00B0D090, _adxt_start_sj)
   *
   * What it does:
   * Starts ADXT decode from one SJ input object, resets playback timing lanes,
   * and starts optional channel-expansion lane when present.
   */
  std::int32_t adxt_start_sj(void* adxtRuntime, void* sourceJoinHandle);

  /**
   * Address: 0x00B0D130 (FUN_00B0D130, _adxt_start_stm)
   *
   * What it does:
   * Rebinds ADXT stream file range and starts stream + SJ decode chain for one
   * runtime object.
   */
  std::int32_t adxt_start_stm(
    void* adxtRuntime,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );

  std::int32_t ADXT_SetLnkSw(void* adxtRuntime, std::int32_t enabled);
  std::int32_t SFTRN_IsSetup(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t transferLaneType);
  std::int32_t SFTRN_CallTrtTrif(
    std::int32_t sfbufHandleAddress,
    std::int32_t transferHandleAddress,
    std::int32_t trifCommandId,
    std::int32_t arg0,
    std::int32_t arg1
  );
  std::int32_t sftrn_ConnBufTrn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBuf0(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufV(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufA(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_ConnTrnBufU(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t sourceLane, std::int32_t targetLane);
  std::int32_t sftrn_BuildUsr(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfset_IsCondValid(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId, std::int32_t value);
  std::int32_t SFSET_SetCond(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId, std::int32_t value);
  std::int32_t SFSET_GetCond(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t conditionId);
  std::int32_t SFXINF_GetStmInf(moho::SfxStreamState* streamState, const char* tagName);
  struct CftYcc420PlanarInputLanes;
  struct CftPixelSurfaceLanes;
  void CFT_Ycc420plnToArgb8888Init();

  /**
   * Address: 0x00AEE730 (FUN_00AEE730, _CFT_Ycc420plnToArgb8888IntInit)
   *
   * What it does:
   * Builds CRI CFT integer YUV->ARGB conversion lookup tables for red/blue/
   * green lanes and one packed intermediate lane.
   */
  void CFT_Ycc420plnToArgb8888IntInit();
  void CFT_Ycc420plnToArgb8888PrgInit();
  struct CftYcc420PlanarPackedWords;
  struct CftRgb16OutputPackedWords;

  /**
   * Address: 0x00AF37F0 (FUN_00AF37F0, _CFT_Ycc420plnToRgb555)
   *
   * What it does:
   * Converts one packed YCC420 source lane into RGB555 using fixed-point
   * clip lookup tables.
   */
  std::int32_t CFT_Ycc420plnToRgb555(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords
  );

  /**
   * Address: 0x00AF3EF0 (FUN_00AF3EF0, _CFT_Ycc420plnToRgb555WithDither)
   *
   * What it does:
   * Converts one packed YCC420 source lane into RGB555 using 4-phase dither
   * clip lookup tables.
   */
  std::int32_t CFT_Ycc420plnToRgb555WithDither(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords
  );

  /**
   * Address: 0x00AF48A0 (FUN_00AF48A0, _CFT_Ycc420plnToRgb565)
   *
   * What it does:
   * Converts one packed YCC420 source lane into RGB565 using fixed-point
   * clip lookup tables.
   */
  std::int32_t CFT_Ycc420plnToRgb565(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords
  );

  /**
   * Address: 0x00AF4FA0 (FUN_00AF4FA0, _CFT_Ycc420plnToRgb565WithDither)
   *
   * What it does:
   * Converts one packed YCC420 source lane into RGB565 using 4-phase dither
   * clip lookup tables.
   */
  std::int32_t CFT_Ycc420plnToRgb565WithDither(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords
  );
  /**
   * Address: 0x00B031B0 (FUN_00B031B0, _cft_sse_Ycc420plnToRgb888Prg)
   *
   * What it does:
   * Converts YCC420 planar lanes to packed RGB888 using MMX lookup tables and
   * a scratch lane for chroma replication/interleave.
   */
  std::uint8_t cft_sse_Ycc420plnToRgb888Prg(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    const __m64* colorTable,
    std::uintptr_t scratchBufferAddress
  );

  /**
   * Address: 0x00B03DC0 (FUN_00B03DC0, _CFT_Ycc420plnToArgb8888Int1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample ARGB8888-int conversion lane based on
   * runtime alignment and stride constraints.
   */
  std::int32_t CFT_Ycc420plnToArgb8888Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    const __m64* colorTable
  );

  /**
   * Address: 0x00B03E30 (FUN_00B03E30, _CFT_Ycc420plnToArgb8888Prg1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample ARGB8888 progressive conversion lane based
   * on runtime alignment and stride constraints.
   */
  std::int32_t CFT_Ycc420plnToArgb8888Prg1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    const __m64* colorTable
  );

  /**
   * Address: 0x00AF2A90 (FUN_00AF2A90, _CFT_Ycc420plnToArgb8888Split)
   *
   * What it does:
   * Repackages YCC420 planar input/output lanes and dispatches split-frame
   * ARGB8888 conversion through user/default table selection.
   */
  std::int32_t CFT_Ycc420plnToArgb8888Split(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords,
    const std::int32_t* userTableAddress
  );

  /**
   * Address: 0x00AEED20 (FUN_00AEED20, _CFT_Ycc420plnToYcc422pix2Int)
   *
   * What it does:
   * Repackages packed conversion lanes and dispatches one-sample or two-sample
   * YCC420->YCC422 conversion path using optimize/alignment rules.
   */
  std::int32_t CFT_Ycc420plnToYcc422pix2Int(
    const CftYcc420PlanarPackedWords* inputWords,
    const CftRgb16OutputPackedWords* outputWords,
    const std::int32_t* scratchBufferWords
  );

  /**
   * Address: 0x00B03EA0 (FUN_00B03EA0, _CFT_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * Chooses scalar or SSE 1-sample YCC420->YCC422 pixel2/int conversion lane
   * based on runtime alignment and stride constraints.
   */
  std::int32_t CFT_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );

  std::int32_t cft_c_Ycc420plnToArgb8888Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );
  std::int32_t cft_sse_Ycc420plnToArgb8888Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    const __m64* colorTable
  );
  std::int32_t cft_c_Ycc420plnToArgb8888Prg1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );
  /**
   * Address: 0x00B05180 (FUN_00B05180, _cft_c_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * Scalar fallback path for YCC420 planar -> YCC422 pixel2/int1 conversion.
   */
  std::uint8_t* cft_c_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );
  /**
   * Address: 0x00AF1B60 (FUN_00AF1B60, _cft_c_Ycc420plnToYcc422pix2Int2smp)
   *
   * What it does:
   * Scalar two-sample conversion path with weighted vertical chroma blending.
   */
  std::uint8_t* cft_c_Ycc420plnToYcc422pix2Int2smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );
  /**
   * Address: 0x00B062C0 (FUN_00B062C0, _cft_sse_Ycc420plnToArgb8888Prg1smp)
   *
   * What it does:
   * MMX fast-path for YCC420 planar -> ARGB8888 conversion using packed
   * lookup-table lanes.
   */
  std::int32_t cft_sse_Ycc420plnToArgb8888Prg1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    const __m64* colorTable
  );
  /**
   * Address: 0x00B06770 (FUN_00B06770, _cft_sse_Ycc420plnToYcc422pix2Int1smp)
   *
   * What it does:
   * MMX fast-path for YCC420 planar -> YCC422 pixel2/int1 interleaved
   * conversion.
   */
  std::int32_t cft_sse_Ycc420plnToYcc422pix2Int1smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface
  );
  /**
   * Address: 0x00B03600 (FUN_00B03600, _cft_sse_Ycc420plnToYcc422pix2Int2smp)
   *
   * What it does:
   * SSE-eligible two-sample conversion lane using caller-provided scratch
   * workspace.
   */
  std::int32_t cft_sse_Ycc420plnToYcc422pix2Int2smp(
    const CftYcc420PlanarInputLanes* inputLanes,
    const CftPixelSurfaceLanes* outputSurface,
    std::uintptr_t scratchBufferAddress,
    std::int32_t scratchBufferSizeBytes
  );
  void CFT_Ycc420plnToRgb565Init();
  void CFT_Ycc420plnToRgb555Init();
  std::int32_t createBitcutClipTable32_555(std::int32_t* table, std::int8_t componentBits, std::int8_t bitShift);
  void createBitcut5GradPtnDitherClipTable32_555(
    std::int32_t* table,
    std::int8_t componentBits,
    std::int8_t bitShift,
    std::int32_t ditherPatternIndex
  );
  std::int32_t createBitcutClipTable32_565(std::int32_t* table, std::int8_t componentBits, std::int8_t bitShift);
  void createBitcut5GradPtnDitherClipTable32_565(
    std::int32_t* table,
    std::int8_t componentBits,
    std::int8_t bitShift,
    std::int32_t ditherPatternIndex
  );
  void SUD_Init();
  std::int32_t SUD_Finish();
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  std::int32_t sfbuf_InitSjUuid();
  void sfbuf_SetSupSj(
    std::int32_t* supplyLaneWords,
    const std::int32_t* createdSjStateWords,
    std::int32_t ownerAddress,
    std::int32_t ownershipMode
  );
  std::int32_t sfbuf_RingGetSub(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outCursor, std::int32_t laneMode);
  std::int32_t sfbuf_RingAddSub(
    std::int32_t sfbufHandleAddress,
    std::int32_t ringIndex,
    std::int32_t advanceCount,
    std::int32_t laneMode
  );
  std::uint32_t sfbuf_ResetConti(std::int32_t* supplyStateWords);
  std::int32_t sfbuf_PeekChunk(
    std::int32_t ringHandleAddress,
    std::int32_t laneMode,
    moho::SjChunkRange* outFirstChunk,
    moho::SjChunkRange* outSecondChunk
  );
  std::int32_t sfbuf_MoveChunk(std::int32_t ringHandleAddress, std::int32_t laneMode, std::int32_t requestedBytes);
  std::int32_t SFX_DecideTableAlph3(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState);
  void SFX_MakeTable(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState, std::int32_t tableMode);
  void sfxcnv_ExecCnvFrmByCbFunc(
    moho::SfxCallbackFrameContext* conversionState,
    moho::SfxStreamState* streamState,
    std::int32_t callbackArg,
    std::int32_t useLookupTable
  );
  void sfxcnv_ExecFullAlphaByCbFunc(
    moho::SfxCallbackFrameContext* conversionState,
    moho::SfxStreamState* streamState,
    std::int32_t callbackArg
  );
  void SFXLIB_Error(moho::SfxCallbackFrameContext* conversionState, moho::SfxStreamState* streamState, const char* message);
  std::int32_t ADXT_IsInitialized();
  void ADXFIC_Init();
  LONG ADXFIC_Finish();
  char* ADXPC_GetVersion();
  const char* cvFsInit();
  void cvFsFinish();
  char* xeCiFinish();
  void xeCiInit();

  /**
   * Address: 0x00B110F0 (FUN_00B110F0, xedir_new_handle)
   *
   * What it does:
   * Returns the first free XECI object lane from the fixed global pool.
   */
  XeciObject* xedir_new_handle();

  /**
   * Address: 0x00B111C0 (FUN_00B111C0, _xeCiOpen)
   *
   * What it does:
   * Opens one XECI stream object and initializes transfer geometry.
   */
  XeciObject* __cdecl xeCiOpen(const char* fileName, std::int32_t openMode, std::int32_t readWriteFlag);

  /**
   * Address: 0x00B11440 (FUN_00B11440, _xeCiReqRead)
   *
   * What it does:
   * Arms one chunked XECI read request and validates DMA/alignment constraints.
   */
  std::int32_t __cdecl xeCiReqRead(XeciObject* object, std::int32_t requestedChunkCount, void* readBuffer);

  /**
   * Address: 0x00B118B0 (FUN_00B118B0, _xeci_create_func)
   *
   * What it does:
   * Opens one file handle for XECI reads, honoring the current read-mode lane.
   */
  HANDLE __cdecl xeci_create_func(LPCSTR fileName);

  /**
   * Address: 0x00B11A90 (FUN_00B11A90, _xeDirSetRootDir)
   *
   * What it does:
   * Resolves and stores one CVFS root directory path and appends a trailing
   * `\\` separator when missing.
   */
  std::int32_t xeDirSetRootDir(const char* rootDirectory);
  std::int32_t cvFsEntryErrFunc(std::int32_t errorCallbackAddress, std::int32_t errorObjectAddress);
  std::int32_t cvFsSetDefDev(const char* deviceName);
  std::int32_t cvFsError_(const char* message);
  void cvFsCallUsrErrFn(std::int32_t errorObjectAddress, const char* message);
  const char* cvFsGetDevName(const CvFsHandleView* handle);
  std::int32_t cvFsOptFn1(CvFsHandleView* handle, std::int32_t optionCode, std::int32_t optionArg0, std::int32_t optionArg1);
  std::int32_t cvFsOptFn2(CvFsHandleView* handle, std::int32_t optionCode, std::int32_t optionArg0, std::int32_t optionArg1);
  std::int32_t cvFsGetMaxByteRate(CvFsHandleView* handle);
  std::int32_t cvFsMakeDir(char* fileName);
  std::int32_t cvFsRemoveDir(char* fileName);
  std::int32_t cvFsDeleteFile(char* fileName);
  std::int32_t cvFsGetFreeSize(const char* deviceName);
  std::int32_t cvFsGetSctLen(CvFsHandleView* handle);
  std::int32_t cvFsSetSctLen(CvFsHandleView* handle);
  std::int32_t cvFsGetNumTr(CvFsHandleView* handle);
  std::int32_t cvFsChangeDir(char* directoryName);
  std::int32_t cvFsIsExistFile(char* fileName);
  std::int32_t cvFsGetNumFiles(char* deviceName);
  std::int32_t cvFsLoadDirInfo(char* fileName, std::int32_t optionArg0, std::int32_t optionArg1);
  char* cvFsGetDefDev();
  std::int32_t cvFsTell(CvFsHandleView* handle);
  std::int32_t cvFsReqRd(CvFsHandleView* handle, std::int32_t bufferAddress, std::int32_t byteCount);
  std::int32_t cvFsReqWr(CvFsHandleView* handle, std::int32_t bufferAddress, std::int32_t byteCount);
  std::int32_t cvFsStopTr(CvFsHandleView* handle);
  void cvFsExecServer();
  std::int32_t cvFsGetFileSizeEx(char* fileName, std::int32_t optionArg);
  std::int32_t cvFsGetFileSizeByHndl(CvFsHandleView* handle);

  /**
   * Address: 0x00B11F40 (FUN_00B11F40, _addDevice)
   *
   * What it does:
   * Registers one CVFS device interface in the fixed device table.
   */
  CvFsDeviceInterfaceView* addDevice(const char* deviceName, void* (__cdecl* deviceFactory)());

  /**
   * Address: 0x00B11FB0 (FUN_00B11FB0, _getDevice)
   *
   * What it does:
   * Resolves one CVFS device name prefix to its registered interface.
   */
  CvFsDeviceInterfaceView* getDevice(const char* deviceName);

  /**
   * Address: 0x00B12040 (FUN_00B12040, _cvFsDelDev)
   *
   * What it does:
   * Clears one CVFS device-table slot by device-name prefix.
   */
  std::int32_t cvFsDelDev(const char* deviceName);

  /**
   * Address: 0x00B12160 (FUN_00B12160, _cvFsOpen)
   *
   * What it does:
   * Opens one CVFS handle through the selected device interface.
   */
  extern "C" CvFsHandleView* cvFsOpen(char* fileName, std::int32_t openMode, std::int32_t openFlags);

  /**
   * Address: 0x00B12290 (FUN_00B12290, _variousProc)
   *
   * What it does:
   * Resolves effective device + rewritten path for CVFS open operations.
   */
  CvFsDeviceInterfaceView* variousProc(char* deviceName, char* filePath, const char* originalPath);

  /**
   * Address: 0x00B12300 (FUN_00B12300, _allocCvFsHn)
   *
   * What it does:
   * Returns one free entry from the fixed CVFS handle pool.
   */
  CvFsHandleView* allocCvFsHn();

  /**
   * Address: 0x00B12350 (FUN_00B12350, _getDevName)
   *
   * What it does:
   * Splits device prefix (`DEV:`) and relative path from one CVFS file name.
   */
  void getDevName(char* outDeviceName, char* outFilePath, const char* fileName);

  /**
   * Address: 0x00B12400 (FUN_00B12400, _getDefDev)
   *
   * What it does:
   * Copies configured default device name into caller buffer.
   */
  char getDefDev(char* outDeviceName);

  std::int32_t cvFsSetCurVolume(char* deviceName, std::int32_t volumeName);
  std::int32_t cvFsAddVolumeEx(
    char* deviceName,
    std::int32_t volumeName,
    std::int32_t imageHandleAddress,
    std::int32_t modeOrFlags
  );
  std::int32_t cvFsDelVolume(char* deviceName, std::int32_t volumeName);
  std::int32_t cvFsGetVolumeInfo(char* deviceName, std::int32_t volumeName, std::int32_t infoCode);
  BOOL cvFsIsExistDevice(char* deviceName);
  std::uint64_t cvFsGetNumTr64(CvFsHandleView* handle);
  std::uint64_t cvFsGetFileSize64(char* fileName);
  std::uint64_t cvFsGetFileSizeEx64(char* fileName, std::int32_t optionArg);

  /**
   * Address: 0x00B13320 (FUN_00B13320, _cvFsSetDefVol)
   *
   * What it does:
   * Dispatches default-volume option request to one CVFS device.
   */
  void cvFsSetDefVol(char* deviceName, std::int32_t volumeName);

  /**
   * Address: 0x00B133B0 (FUN_00B133B0, _isNeedDevName)
   *
   * What it does:
   * Queries whether one CVFS device requires explicit device-prefix paths.
   */
  std::int32_t isNeedDevName(char* deviceName);

  /**
   * Address: 0x00B133E0 (FUN_00B133E0, _addDevName)
   *
   * What it does:
   * Prefixes `DEV:` onto one path when the target device requires it.
   */
  std::int32_t addDevName(char* deviceName, char* filePath);

  extern "C" std::int32_t cvFsGetFsys64Info(CvFsHandleView* handle);

  void* mfCiGetInterface();
  CvFsUserErrorBridgeFn __cdecl mfCiEntryErrFunc(CvFsUserErrorBridgeFn callbackFunction, std::int32_t callbackObject);
  void mfCiExecHndl();
  void mfCiExecServer();
  std::int32_t __cdecl mfci_call_errfn(std::int32_t callbackObject, const char* errorMessage);
  std::uint32_t __cdecl mfci_strtoul(const char* text, const char** outNextText, std::int32_t base);
  std::uint32_t __cdecl mfci_get_adr_size(const char* addressAndSizeText, std::uint32_t* outSizeBytes);
  std::int32_t __cdecl mfci_alloc();
  std::int32_t __cdecl mfci_free(std::int32_t handleAddress);
  std::int32_t __cdecl mfci_reset_hn(std::int32_t handleAddress);
  void __cdecl mfCiClose(std::int32_t handleAddress);
  std::int32_t __cdecl mfCiSeek(std::int32_t handleAddress, std::int32_t seekOffset, std::int32_t seekOrigin);
  std::int32_t __cdecl mfCiTell(std::int32_t handleAddress);
  void __cdecl mfCiStopTr(std::int32_t handleAddress);
  std::int32_t __cdecl mfCiGetStat(std::int32_t handleAddress);
  std::int32_t __cdecl mfCiGetFileSize(const char* fileNameOrAddressRange);
  void mfCrsLock();
  void mfCrsUnlock();
  std::int32_t(__cdecl* xeCiEntryErrFunc(
    std::int32_t(__cdecl* callbackFunction)(std::int32_t callbackObject, const char* errorMessage, std::int32_t errorCode),
    std::int32_t callbackObject
  ))(std::int32_t callbackObject, const char* errorMessage, std::int32_t errorCode);
  void __stdcall xeci_OnReadCompletionStatus(std::int32_t errorCode, std::int32_t bytesRead, OVERLAPPED* overlapped);
  std::int32_t __cdecl xeCiClose(XeciObject* object);
  void __cdecl xeCiStopTr(XeciObject* object);
  void* xeCiGetInterface();
  /**
   * Address: 0x00B0CE90 (FUN_00B0CE90, _adxt_detach_ahx)
   *
   * What it does:
   * Dispatches ADXT AHX detach through installed AHX detach callback lane.
   */
  void adxt_detach_ahx();
  /**
   * Address: 0x00B0CEA0 (FUN_00B0CEA0, _adxt_detach_mpa)
   * Also emitted at: 0x00B0F010 (FUN_00B0F010, _ADXT_DetachMpa)
   *
   * What it does:
   * Dispatches ADXT MPEG-audio detach through installed detach callback lane.
   */
  std::int32_t ADXT_DetachMpa();
  /**
   * Address: 0x00B0CB60 (FUN_00B0CB60, _ADXT_Create)
   *
   * What it does:
   * Creates one ADXT runtime under ADXCRS enter/leave guards.
   */
  void* ADXT_Create(std::int32_t maxChannelCount, void* workBuffer, std::int32_t workBytes);
  /**
   * Address: 0x00B0CE20 (FUN_00B0CE20)
   *
   * What it does:
   * Creates one ADXT runtime with Dolby Pro Logic II setup under ADXCRS guards.
   */
  void* ADXT_CreateDolbyProLogicII(void* workBuffer, std::int32_t workBytes);
  /**
   * Address: 0x00B0CE50 (FUN_00B0CE50)
   *
   * What it does:
   * Creates one 2-channel ADXT runtime using remaining work area and attaches
   * Dolby Pro Logic II state from the reserved lead block.
   */
  void* adxt_CreateDolbyProLogicII(void* workBuffer, std::int32_t workBytes);
  void* adxt_Create(std::int32_t maxChannelCount, void* workBuffer, std::int32_t workBytes);
  std::int32_t ADXT_AttachDolbyProLogicII(void* adxtRuntime, void* workBuffer, std::int32_t workBytes);
  /**
   * Address: 0x00B0F010 (FUN_00B0F010, _ADXT_DetachMpa)
   *
   * What it does:
   * Dispatches ADXT MPEG-audio detach through the installed link callback lane.
   */
  void adxt_detach_mpa(void* adxtRuntime);
  /**
   * Address: 0x00B0F2C0 (FUN_00B0F2C0, _ADXT_DetachMPEG2AAC)
   *
   * What it does:
   * Dispatches ADXT MPEG-2 AAC detach through the installed link callback lane.
   */
  void adxt_detach_m2a(void* adxtRuntime);
  void adxt_Stop(void* adxtRuntime);
  std::int32_t ADXB_SetAhxInSj(moho::AdxBitstreamDecoderState* decoder);
  std::uint32_t ADXB_SetAhxDecSmpl(moho::AdxBitstreamDecoderState* decoder, std::int32_t maxDecodeSamples);
  std::int32_t ADXB_AhxTermSupply(moho::AdxBitstreamDecoderState* decoder);
  moho::AdxBitstreamDecoderState* ADXB_SetCbDec(
    moho::AdxBitstreamDecoderState* decoder,
    std::int32_t(__cdecl* callback)(std::int32_t, std::int32_t, std::int32_t),
    std::int32_t callbackContext
  );
  std::int32_t ADXB_ExecHndl(moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXB_GetDecDtLen(const moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXB_GetDecNumSmpl(const moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXB_Reset(moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXSJD_Create(
    std::int32_t inputSourceHandleAddress,
    std::int32_t outputHandleCount,
    std::int32_t* outputHandleAddresses
  );
  std::int32_t adxsjd_get_wr(
    std::int32_t callbackContext,
    std::int32_t* outWriteOffsetSamples,
    std::int32_t* outWritableSamples,
    std::int32_t* outUntilTrapSamples
  );
  std::int32_t ADXSJD_Stop(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetInSj(std::int32_t sjdHandle, void* sourceJoinHandle);
  std::int32_t ADXSJD_SetOutSj(std::int32_t sjdHandle, std::int32_t outputLane, void* outputHandle);
  std::uint32_t ADXSJD_SetMaxDecSmpl(std::int32_t sjdHandle, std::int32_t maxDecodeSamples);
  std::int32_t ADXSJD_Start(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetDecPos(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetDecPos(std::int32_t sjdHandle, std::int32_t decodePosition);
  std::int32_t ADXSJD_SetCbDec(std::int32_t sjdHandle, void* callbackAddress, std::int32_t callbackContext);
  std::int32_t ADXSJD_SetLnkSw(std::int32_t sjdHandle, std::int32_t enabled);
  std::int32_t ADXSJD_GetLnkSw(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetNumChan(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetOutBps(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetBlkSmpl(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetBlkLen(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetTotalNumSmpl(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetCof(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetNumLoop(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetLpInsNsmpl(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetLpStartPos(std::int32_t sjdHandle);
  std::int16_t ADXSJD_GetDefPan(std::int32_t sjdHandle, std::int32_t laneIndex);
  std::int32_t ADXSJD_SetDefFmt(std::int32_t sjdHandle, std::int32_t requestedFormat);
  std::int32_t ADXSJD_GetLpStartOfst(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetLpEndPos(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetLpEndOfst(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetAinfLen(std::int32_t sjdHandle);
  std::int16_t ADXSJD_GetDefOutVol(std::int32_t sjdHandle);
  std::uint8_t* ADXSJD_GetDataId(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetHdrLen(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetFmtBps(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetSpsdInfo(std::int32_t sjdHandle);
  std::int32_t ADXSJD_TakeSnapshot(std::int32_t sjdHandle);
  std::int32_t ADXSJD_RestoreSnapshot(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetDecDtLen(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetTrapNumSmpl(std::int32_t sjdHandle, std::int32_t trapSampleCount);
  std::int32_t ADXSJD_GetTrapNumSmpl(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetTrapCnt(std::int32_t sjdHandle, std::int32_t trapCount);
  std::int32_t ADXSJD_GetTrapCnt(std::int32_t sjdHandle);
  std::int32_t ADXSJD_SetTrapDtLen(std::int32_t sjdHandle, std::int32_t trapDataLengthBytes);
  std::int32_t ADXSJD_GetTrapDtLen(std::int32_t sjdHandle);
  std::int32_t ADXSJD_EntryTrapFunc(std::int32_t sjdHandle, void* callbackAddress, std::int32_t callbackContext);
  std::int32_t ADXSJD_EntryFltFunc(std::int32_t sjdHandle, void* callbackAddress, std::int32_t callbackContext);
  std::int32_t ADXSJD_AdjustSmpl(std::int32_t sjdHandle, std::int32_t sampleDelta);
  moho::AdxBitstreamDecoderState* ADXSJD_SetExtString(std::int32_t sjdHandle, const char* extString);
  std::int32_t ADXSJD_SetDefExtString(const char* extString);
  std::int16_t ADXSJD_GetExtParams(
    std::int32_t sjdHandle,
    std::int16_t* outK0,
    std::int16_t* outKMultiplier,
    std::int16_t* outKAdder
  );
  moho::AdxBitstreamDecoderState* ADXSJD_SetExtParams(
    std::int32_t sjdHandle,
    std::int16_t k0,
    std::int16_t kMultiplier,
    std::int16_t kAdder
  );
  std::int32_t ADXSJD_GetFormat(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetSfreq(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetStat(std::int32_t sjdHandle);
  std::int32_t ADXSJD_GetDecNumSmpl(std::int32_t sjdHandle);
  std::int32_t ADXSJD_TermSupply(std::int32_t sjdHandle);
  std::int32_t ADXAMP_Start(void* channelExpandHandle);
  void ADXAMP_Stop(void* channelExpandHandle);
  void CRIERR_CallErr(const char* message);
  std::int32_t j__CRIERR_SetCbErr(moho::AdxmErrorCallback callbackFunction, std::int32_t callbackObject);
  std::int32_t ADXRNA_EntryErrFunc(moho::AdxmErrorCallback callbackFunction, std::int32_t callbackObject);
  std::int32_t ADXRNA_Create(std::int32_t sourceJoinHandleTableAddress, std::int32_t channelCount);
  std::int32_t ADXRNA_GetNumData(std::int32_t rnaHandle);
  void ADXRNA_ExecHndl(std::int32_t rnaHandle);
  void j__ADXRNA_Stop(std::int32_t rnaHandle);
  void j__ADXRNA_SetTransSw(std::int32_t rnaHandle, std::int32_t enabled);
  void j__ADXRNA_SetPlaySw(std::int32_t rnaHandle, std::int32_t enabled);
  void ADXRNA_Destroy(std::int32_t rnaHandle);
  void* mwRnaCreate(std::int32_t sourceJoinHandleTableAddress, std::int32_t channelCount);
  void ADXSJD_Destroy(std::int32_t sjdHandle);
  void* adxf_AllocAdxFs();
  struct AdxstmServerSlotView;
  /**
   * Address: 0x00B0F4A0 (FUN_00B0F4A0)
   *
   * What it does:
   * Increments SFADXT attach/reference count lane.
   */
  void sfadxt_IncrementAttachCount();
  /**
   * Address: 0x00B0F4B0 (FUN_00B0F4B0)
   *
   * What it does:
   * Decrements SFADXT attach/reference count lane.
   */
  void sfadxt_DecrementAttachCount();
  /**
   * Address: 0x00B0F5E0 (FUN_00B0F5E0, _ADXT_SetupRtimeNumStm)
   *
   * What it does:
   * Stores ADXSTM realtime-partition slot count.
   */
  std::int32_t ADXT_SetupRtimeNumStm(std::int32_t realtimeStreamCount);
  /**
   * Address: 0x00B0F5F0 (FUN_00B0F5F0, _ADXT_SetupNrmlNumStm)
   *
   * What it does:
   * Stores ADXSTM normal-partition slot count and derives normal-partition
   * start offset from fixed 0x50-slot pool.
   */
  std::int32_t ADXT_SetupNrmlNumStm(std::int32_t normalStreamCount);
  /**
   * Address: 0x00B0F610 (FUN_00B0F610, _ADXSTM_Init)
   *
   * What it does:
   * Increments ADXSTM init count and clears global 0x1E00 slot pool on first
   * initialization.
   */
  std::int32_t ADXSTM_Init();
  /**
   * Address: 0x00B0F640 (FUN_00B0F640, _ADXSTM_Reset)
   *
   * What it does:
   * Compatibility reset entrypoint (no-op in this runtime variant).
   */
  void ADXSTM_Reset();
  /**
   * Address: 0x00B0F670 (FUN_00B0F670, _ADXSTM_Create)
   *
   * What it does:
   * Lock-wrapper create entry that brackets `adxstm_Create` with enter/leave;
   * routes to normal/realtime slot partitions from reserve threshold.
   */
  void* ADXSTM_Create(moho::SofdecSjSupplyHandle* sourceJoinObject, std::int32_t reserveSectors);
  /**
   * Address: 0x00B0F650 (FUN_00B0F650, _ADXSTM_Finish)
   *
   * What it does:
   * Decrements ADXSTM init-count and clears ADXSTM object-pool when it reaches
   * zero.
   */
  std::int32_t ADXSTM_Finish();
  /**
   * Address: 0x00B0F6C0 (FUN_00B0F6C0, _adxstm_Create)
   *
   * What it does:
   * Chooses normal vs realtime ADXSTM slot partition from reserve threshold and
   * allocates one stream slot.
   */
  void* adxstm_Create(moho::SofdecSjSupplyHandle* sourceJoinObject, std::int32_t reserveSectors);
  /**
   * Address: 0x00B0F700 (FUN_00B0F700, _ADXSTMF_CreateCvfsRt)
   *
   * What it does:
   * Allocates one free ADXSTM slot from realtime partition and seeds runtime
   * lanes.
   */
  void* ADXSTMF_CreateCvfsRt(
    CvFsHandleView* cvfsHandle,
    std::int32_t baseOffset,
    std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* sourceJoinObject
  );
  /**
   * Address: 0x00B0F760 (FUN_00B0F760, _ADXSTMF_SetupHandleMember)
   *
   * What it does:
   * Initializes one ADXSTM runtime slot with source/file window lanes and
   * default stream state.
   */
  void ADXSTMF_SetupHandleMember(
    AdxstmServerSlotView* streamHandle,
    CvFsHandleView* cvfsHandle,
    std::int32_t baseOffset,
    std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* sourceJoinObject
  );
  /**
   * Address: 0x00B0F810 (FUN_00B0F810, _ADXSTMF_CreateCvfs)
   *
   * What it does:
   * Allocates one free ADXSTM slot from normal partition and seeds runtime
   * lanes.
   */
  void* ADXSTMF_CreateCvfs(
    CvFsHandleView* cvfsHandle,
    std::int32_t baseOffset,
    std::int32_t fileLengthBytes,
    moho::SofdecSjSupplyHandle* sourceJoinObject
  );
  /**
   * Address: 0x00B0FBC0 (FUN_00B0FBC0, _ADXSTM_EntryEosFunc)
   *
   * What it does:
   * Export thunk that forwards EOS callback registration into ADXSTM runtime.
   */
  std::int32_t
  ADXSTM_EntryEosFunc(std::int32_t streamHandleAddress, std::int32_t callbackAddress, std::int32_t callbackContext);
  /**
   * Address: 0x00B0FB30 (FUN_00B0FB30, _ADXSTM_StopNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking stop state into ADXSTM runtime.
   */
  void ADXSTM_StopNw(void* streamHandle);
  /**
   * Address: 0x00B0F960 (FUN_00B0F960, _ADXSTM_ReleaseFileNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking release-state transition.
   */
  void ADXSTM_ReleaseFileNw(void* streamHandle);
  /**
   * Address: 0x00B0F9A0 (FUN_00B0F9A0, _ADXSTM_ReleaseFile)
   *
   * What it does:
   * Export thunk that stops and drains one ADXSTM stream before file release.
   */
  void ADXSTM_ReleaseFile(void* streamHandle);
  /**
   * Address: 0x00B0F8B0 (FUN_00B0F8B0, _ADXSTM_BindFileNw)
   *
   * What it does:
   * Export thunk that forwards non-blocking file bind lane update.
   */
  void ADXSTM_BindFileNw(
    void* streamHandle,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  /**
   * Address: 0x00B0F920 (FUN_00B0F920, _ADXSTM_BindFile)
   *
   * What it does:
   * Export thunk that forwards blocking file-bind workflow.
   */
  std::int8_t ADXSTM_BindFile(
    void* streamHandle,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  /**
   * Address: 0x00B0FBF0 (FUN_00B0FBF0, _ADXSTM_SetEos)
   *
   * What it does:
   * Export thunk that updates ADXSTM end-of-stream sector lane.
   */
  std::int32_t ADXSTM_SetEos(void* streamHandle, std::int32_t eosSector);
  /**
   * Address: 0x00B10110 (FUN_00B10110, _ADXSTM_SetBufSize)
   *
   * What it does:
   * Export thunk that forwards ADXSTM buffer-size lane update.
   */
  std::int32_t ADXSTM_SetBufSize(void* streamHandle, std::int32_t minBufferSectors, std::int32_t maxBufferSectors);
  /**
   * Address: 0x00B10140 (FUN_00B10140, _ADXSTM_SetReqRdSize)
   *
   * What it does:
   * Export thunk that forwards requested-read sector lane update.
   */
  std::int32_t ADXSTM_SetReqRdSize(void* streamHandle, std::int32_t requestedSectors);
  /**
   * Address: 0x00B10090 (FUN_00B10090, _ADXSTM_GetCurOfst)
   *
   * What it does:
   * Export thunk that forwards current ADXSTM offset query.
   */
  std::int32_t ADXSTM_GetCurOfst(void* streamHandle, std::int32_t* outCurrentOffset);
  /**
   * Address: 0x00B100C0 (FUN_00B100C0, _ADXSTM_GetBufSize)
   *
   * What it does:
   * Export thunk that forwards ADXSTM buffered readable/writable size query.
   */
  std::int32_t ADXSTM_GetBufSize(
    void* streamHandle,
    std::int32_t* outWritableBytes,
    std::int32_t* outReadableBytes
  );
  /**
   * Address: 0x00B101E0 (FUN_00B101E0, _ADXSTM_SetPause)
   *
   * What it does:
   * Export thunk that forwards one pause-byte write into ADXSTM runtime lane.
   */
  std::int8_t ADXSTM_SetPause(void* streamHandle, std::int32_t paused);
  /**
   * Address: 0x00B10200 (FUN_00B10200, _ADXSTM_GetPause)
   *
   * What it does:
   * Export thunk that forwards one pause-byte read from ADXSTM runtime lane.
   */
  std::int32_t ADXSTM_GetPause(void* streamHandle);
  /**
   * Address: 0x00B10220 (FUN_00B10220, _ADXSTM_GetCvdfsStat)
   *
   * What it does:
   * Returns CVFS status from one ADXSTM runtime handle and mirrors it to out lane.
   */
  std::int32_t ADXSTM_GetCvdfsStat(void* streamHandle, std::int32_t* outStatus);
  /**
   * Address: 0x00B10240 (FUN_00B10240, _ADXSTM_GetFad)
   *
   * What it does:
   * Returns fixed FAD state by writing `0` into caller output lane.
   */
  std::int32_t ADXSTM_GetFad(void* streamHandle, std::int32_t* outFad);
  /**
   * Address: 0x00B10250 (FUN_00B10250, _ADXSTM_GetFsizeSct)
   *
   * What it does:
   * Export thunk that forwards file-size-in-sectors query.
   */
  std::int32_t ADXSTM_GetFsizeSct(char* fileName, std::int32_t* outSectorCount);
  /**
   * Address: 0x00B102A0 (FUN_00B102A0, _ADXSTM_GetFsizeByte)
   *
   * What it does:
   * Export thunk that forwards file-size-in-bytes query.
   */
  std::int32_t ADXSTM_GetFsizeByte(char* fileName, std::int32_t* outFileSizeBytes);
  /**
   * Address: 0x00B102D0 (FUN_00B102D0, _ADXSTM_SetSj)
   *
   * What it does:
   * Export thunk that binds SJ supply handle to one ADXSTM runtime handle.
   */
  std::int32_t ADXSTM_SetSj(void* streamHandle, void* sourceJoinObject);
  /**
   * Address: 0x00B10320 (FUN_00B10320, _ADXSTM_SetRdSct)
   *
   * What it does:
   * Export thunk that updates ADXSTM read-sector window lanes.
   */
  std::int32_t ADXSTM_SetRdSct(void* streamHandle, std::int32_t readSectors);
  /**
   * Address: 0x00B10350 (FUN_00B10350, _ADXSTM_SetOfst)
   *
   * What it does:
   * Export thunk that updates ADXSTM base-offset lane and restarts seek.
   */
  std::int32_t ADXSTM_SetOfst(void* streamHandle, std::int32_t baseOffset);
  /**
   * Address: 0x00B0FA10 (FUN_00B0FA10, _ADXSTM_Seek)
   *
   * What it does:
   * Export thunk that updates one ADXSTM sector offset lane.
   */
  std::int32_t ADXSTM_Seek(void* streamHandle, std::int32_t sectorOffset);
  /**
   * Address: 0x00B0FAB0 (FUN_00B0FAB0, _ADXSTM_Start)
   *
   * What it does:
   * Export thunk that starts ADXSTM stream using default sector limit lane.
   */
  std::int32_t ADXSTM_Start(void* streamHandle);
  /**
   * Address: 0x00B0FAF0 (FUN_00B0FAF0, _ADXSTM_Start2)
   *
   * What it does:
   * Export thunk that starts ADXSTM stream using caller sector limit lane.
   */
  std::int32_t ADXSTM_Start2(void* streamHandle, std::int32_t sectorCount);
  /**
   * Address: 0x00B0F9F0 (FUN_00B0F9F0, _ADXSTM_GetStat)
   *
   * What it does:
   * Export thunk that reads current ADXSTM stream status byte lane.
   */
  std::int32_t ADXSTM_GetStat(void* streamHandle);
  /**
   * Address: 0x00B101C0 (FUN_00B101C0, _ADXSTM_GetFileSize)
   *
   * What it does:
   * Export thunk that forwards file-size query into ADXSTM file-size lane.
   */
  std::int32_t ADXSTM_GetFileSize(char* fileName);
  std::int32_t ADXSTM_GetFileLen(void* streamHandle);
  std::int32_t ADXSTM_GetReadFlg(void* streamHandle);
  /**
   * Address: 0x00B0FA40 (FUN_00B0FA40, _ADXSTM_Tell)
   *
   * What it does:
   * Export thunk that reads one ADXSTM current sector-offset lane.
   */
  std::int32_t ADXSTM_Tell(void* streamHandle);
  /**
   * Address: 0x00B0FB80 (FUN_00B0FB80, _ADXSTM_Stop)
   *
   * What it does:
   * Export thunk that stops ADXSTM stream and drains filesystem service.
   */
  void ADXSTM_Stop(void* streamHandle);
  /**
   * Address: 0x00B0F870 (FUN_00B0F870, _ADXSTM_Destroy)
   *
   * What it does:
   * Export thunk that forwards ADXSTM teardown into `adxstm_Destroy`.
   */
  std::int32_t ADXSTM_Destroy(void* streamHandle);
  /**
   * Address: 0x00B10010 (FUN_00B10010, _ADXSTM_ExecServer)
   *
   * What it does:
   * Export thunk that forwards one ADXSTM worker-server tick.
   */
  void ADXSTM_ExecServer();
  /**
   * Address: 0x00B10070 (FUN_00B10070, _ADXSTM_ExecFsSvr)
   *
   * What it does:
   * Export thunk that forwards one ADXSTM filesystem-server tick.
   */
  void ADXSTM_ExecFsSvr();
  std::int32_t adxf_Stop(void* adxfHandle);
  std::int32_t adxf_Seek(void* adxfHandle, std::int32_t seekOffset, std::int32_t seekOrigin);
  std::int32_t adxf_Tell(void* adxfHandle);
  std::int32_t adxf_RefreshFsizeSct(void* adxfHandle);
  std::int32_t adxf_GetFsizeSct(void* adxfHandle);
  std::int32_t adxf_GetNumReqSct(void* adxfHandle, std::int32_t* outRequestedSectorStart);
  std::int32_t adxf_GetNumReadSct(void* adxfHandle);
  void adxf_CloseSjStm(void* adxfHandle);
  void adxf_Close(void* adxfHandle);
  void adxf_CloseAll();
  void* adxf_CreateAdxFs();
  void* adxf_OpenAfsNw(void* afsPointHandle, std::int32_t fileIndex);
  std::int32_t adxf_GetFnameRangeEx(
    std::int32_t afsHandle,
    std::int32_t fileIndex,
    char* outFileName,
    std::int32_t* outStartOffset,
    std::int32_t* outRangeStart,
    std::int32_t* outRangeEnd
  );
  const char* adxf_GetFnameFromPt(std::int32_t afsHandle);
  std::int32_t adxf_SetAfsFileInfo(void* adxfHandle, void* afsPointHandle, std::int32_t fileIndex);
  std::int32_t adxf_SetFileInfoEx(void* adxfHandle, void* afsPointHandle, std::int32_t fileIndex);
  std::int32_t adxf_SetFileInfoRangeNw(
    void* adxfHandle,
    const char* fileName,
    std::int32_t startOffset,
    std::int32_t rangeStart,
    std::int32_t rangeEnd
  );
  void* adxf_OpenRangeNw(const char* fileName, std::int32_t startOffset, std::int32_t rangeStart, std::int32_t rangeEnd);
  /**
   * Address: 0x00B0A520 (FUN_00B0A520, _ADXF_CALC_BYTE2SCT)
   *
   * What it does:
   * Converts byte-count lane to 2048-byte sector count with ceil division.
   */
  std::int32_t ADXF_CALC_BYTE2SCT(std::int32_t byteCount);
  /**
   * Address: 0x00B0A550 (FUN_00B0A550, _adxf_SetCmdHstry)
   *
   * What it does:
   * Appends one ADXF command history entry and updates per-command call count.
   */
  std::int32_t adxf_SetCmdHstry(
    std::int32_t commandId,
    std::int32_t commandStage,
    void* handleArg0,
    std::int32_t arg1,
    std::int32_t arg2
  );
  std::int32_t adxf_ReadSj32(void* adxfHandle, std::int32_t requestedSectors, void* sourceJoinObject);
  std::int32_t adxf_ReadNw32(void* adxfHandle, std::int32_t requestedSectors, std::int32_t readMode);
  std::int32_t adxf_GetStat(void* adxfHandle);
  void adxf_wait_until_file_open(void* streamHandle);
  std::int32_t adxf_GetPtStat(std::int32_t pointId);
  std::int32_t adxf_GetPtStatJumpThunk(std::int32_t pointId);
  std::int32_t adxf_CloseLdptnwHn();
  std::int32_t adxf_StopPtLd();
  std::int32_t SofdecSetMonoRoutingMode(std::int32_t monoRoutingMode);
  std::int32_t SofdecGetMonoRoutingMode();
  std::int32_t SofdecSetBufferPlacementMode(std::int32_t bufferPlacementMode);
  std::int32_t ADXM_SetInterval1(std::int32_t interval);
  std::int32_t adxf_LoadPtBothNw(
    std::int32_t arg0,
    std::int32_t arg1,
    std::int32_t arg2,
    char* arg3,
    std::int32_t arg4,
    std::int32_t arg5,
    std::int32_t arg6,
    char* arg7,
    char* arg8,
    std::int32_t arg9,
    std::int32_t arg10
  );
  void adxf_wait_1ms();
  std::int32_t adxf_ChkPrmPt(std::int32_t pointId, const void* pointInfo);
  std::int32_t adxf_LoadPartition(std::int32_t arg0, char* arg1, std::int32_t arg2, char* arg3);
  std::int32_t adxf_LoadPartitionEx(std::int32_t arg0, char* arg1, std::int32_t arg2, char* arg3);
  std::int32_t adxf_LoadPartitionNw(std::int32_t arg0, char* arg1, std::int32_t arg2, char* arg3);
  std::int32_t adxf_LoadPtRangeNwEx(
    std::int32_t arg0,
    char* arg1,
    std::int32_t arg2,
    std::int32_t arg3,
    std::int32_t arg4,
    char* arg5,
    char* arg6,
    std::int32_t arg7
  );
  std::int32_t adxf_LoadPartitionRangeNw(
    std::int32_t arg0,
    char* arg1,
    std::int32_t arg2,
    std::int32_t arg3,
    std::int32_t arg4,
    char* arg5
  );

  /**
   * Address: 0x00B0BB30 (FUN_00B0BB30, _adxf_ExecOne)
   *
   * What it does:
   * Updates one ADXF handle polling lane and closes SJ transfer when stream
   * status reaches terminal/stop conditions.
   */
  void adxf_ExecOne(void* adxfHandle);

  /**
   * Address: 0x00B0BBD0 (FUN_00B0BBD0, _adxf_ExecServer)
   *
   * What it does:
   * Runs ADXF per-handle polling over the ADXF handle pool under ADXCRS lock.
   */
  void adxf_ExecServer();

  /**
   * Address: 0x00B0BBC0 (FUN_00B0BBC0, _ADXF_ExecServer)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_ExecServer`.
   */
  void ADXF_ExecServer();

  /**
   * Address: 0x00B0B9D0 (FUN_00B0B9D0, _ADXF_Stop)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_Stop`.
   */
  std::int32_t ADXF_Stop(void* adxfHandle);

  /**
   * Address: 0x00B0BC00 (FUN_00B0BC00, _ADXF_Seek)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_Seek`.
   */
  std::int32_t ADXF_Seek(void* adxfHandle, std::int32_t seekOffset, std::int32_t seekOrigin);

  /**
   * Address: 0x00B0BCE0 (FUN_00B0BCE0, _ADXF_Tell)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_Tell`.
   */
  std::int32_t ADXF_Tell(void* adxfHandle);

  /**
   * Address: 0x00B0BD20 (FUN_00B0BD20)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_RefreshFsizeSct`.
   */
  std::int32_t ADXF_RefreshFsizeSct(void* adxfHandle);

  /**
   * Address: 0x00B0BD70 (FUN_00B0BD70, _ADXF_GetFsizeSct)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_GetFsizeSct`.
   */
  std::int32_t ADXF_GetFsizeSct(void* adxfHandle);

  /**
   * Address: 0x00B0BDF0 (FUN_00B0BDF0, _ADXF_GetNumReqSct)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_GetNumReqSct`.
   */
  std::int32_t ADXF_GetNumReqSct(void* adxfHandle, std::int32_t* outRequestedSectorStart);

  /**
   * Address: 0x00B0BE60 (FUN_00B0BE60, _ADXF_GetNumReadSct)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_GetNumReadSct`.
   */
  std::int32_t ADXF_GetNumReadSct(void* adxfHandle);

  /**
   * Address: 0x00B0BEA0 (FUN_00B0BEA0, _ADXF_GetStat)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_GetStat`.
   */
  std::int32_t ADXF_GetStat(void* adxfHandle);

  /**
   * Address: 0x00B0B300 (FUN_00B0B300, _ADXF_OpenRangeNw)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_OpenRangeNw`.
   */
  void* ADXF_OpenRangeNw(const char* fileName, std::int32_t startOffset, std::int32_t rangeStart, std::int32_t rangeEnd);

  /**
   * Address: 0x00B0B4D0 (FUN_00B0B4D0, _ADXF_OpenAfsNw)
   *
   * What it does:
   * ADXF lock-guarded wrapper around `adxf_OpenAfsNw`.
   */
  void* ADXF_OpenAfsNw(void* afsPointHandle, std::int32_t fileIndex);
  void ADXT_ExecFsSvr();
  void adxt_ExecFsSvr();
  void adxt_ExecFsServer();
  void ADXT_ExecFsServer();
  /**
   * Address: 0x00B0FEC0 (FUN_00B0FEC0, _ADXSTMF_ExecHndl)
   *
   * What it does:
   * Runs one ADXSTM filesystem-handle service lane.
   */
  std::int32_t ADXSTMF_ExecHndl(void* streamHandle);
  std::int32_t ADXT_IsActiveFsSvr();
  void ADXCRS_Enter();
  void ADXCRS_Leave();
  /**
   * Address: 0x00B10060 (FUN_00B10060, _adxstm_test_and_set)
   *
   * What it does:
   * ADXSTM thunk wrapper around `SVM_TestAndSet`.
   */
  BOOL adxstm_test_and_set(std::int32_t* signalLane);
  std::int32_t LSC_CallErrFunc_(const char* format, ...);
  void SVM_CallErr1(const char* message);
  void LSC_Destroy(void* lscHandle);
  void ADXAMP_Destroy(void* channelExpandHandle);
  int ADX_DecodeSteFloatAsMono(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t decodeScale,
    float scaleFactor
  );
  int ADX_DecodeSteFloatAsSte(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t decodeScale,
    float scaleFactor
  );

  std::int32_t __cdecl HEAPMNG_Create(void* heapBuffer, std::uint32_t heapByteCount, void** outHeapManager);
  std::int32_t __cdecl HEAPMNG_Destroy(void* heapManagerHandle);
  int HEAPMNG_Allocate(int heapManagerHandle, SIZE_T byteCount, int* outPointer);
  int HEAPMNG_Free(int heapManagerHandle, int pointerValue);

  void SJCRS_Init();
  std::int32_t SJCRS_Finish();

  /**
   * Address: 0x00B0C310 (FUN_00B0C310, _SVM_UnlockThrd)
   *
   * What it does:
   * Leaves SVM lock lane with thread-domain lock token `5`.
   */
  void SVM_UnlockThrd();

  /**
   * Address: 0x00B0C320 (FUN_00B0C320, _SVM_UnlockEtc)
   *
   * What it does:
   * Leaves SVM lock lane with auxiliary-domain lock token `1000`.
   */
  void SVM_UnlockEtc();

  /**
   * Address: 0x00B0C3C0 (FUN_00B0C3C0, _SVM_CallErr2)
   *
   * What it does:
   * Builds SVM error text as `prefix + message` and dispatches registered
   * SVM error callback lane.
   */
  void SVM_CallErr2(const char* prefix, const char* message);

  /**
   * Address: 0x00B0C410 (FUN_00B0C410)
   *
   * What it does:
   * Encodes one integer lane into the legacy SVM scratch format and copies
   * a reversed scratch-window prefix into caller output.
   */
  std::int32_t SVM_ItoA(std::int32_t value, char* outText, std::int32_t outBytes);

  /**
   * Address: 0x00B0C470 (FUN_00B0C470)
   *
   * What it does:
   * Formats two integer lanes into one legacy SVM text payload using
   * `SVM_ItoA` and a single-space separator.
   */
  std::int32_t SVM_ItoA2(std::int32_t highWord, std::int32_t lowWord, char* outText, std::int32_t outBytes);

  /**
   * Address: 0x00B0C340 (FUN_00B0C340, _SVM_CallErr)
   *
   * What it does:
   * Formats one SVM error message and dispatches it through registered
   * SVM error-callback lane.
   */
  void SVM_CallErr(const char* format, ...);

  /**
   * Address: 0x00B0C1E0 (FUN_00B0C1E0, _svm_lock)
   *
   * What it does:
   * Executes one configured SVM lock callback and updates lock nesting/type
   * state.
   */
  void svm_lock(std::int32_t lockType);

  /**
   * Address: 0x00B0C230 (FUN_00B0C230, _svm_unlock)
   *
   * What it does:
   * Executes one configured SVM unlock callback and validates lock-type
   * symmetry when leaving the outermost lock level.
   */
  void svm_unlock(std::int32_t lockType);

  /**
   * Address: 0x00B0C1D0 (FUN_00B0C1D0, _SVM_Lock)
   *
   * What it does:
   * Enters SVM lock lane using default lock-type token `1`.
   */
  void SVM_Lock();

  /**
   * Address: 0x00B0C220 (FUN_00B0C220, _SVM_Unlock)
   *
   * What it does:
   * Leaves SVM lock lane using default lock-type token `1`.
   */
  void SVM_Unlock();
  int M2ABSR_Read(std::int32_t bitstreamHandle, std::int32_t bitCount, void* outBits);
  int M2ABSR_Tell(std::int32_t bitstreamHandle, std::int32_t* outBitPosition);
  int M2ABSR_Seek(std::int32_t bitstreamHandle, std::int32_t bitPosition, std::int32_t origin);
  int M2ABSR_Overruns(std::int32_t bitstreamHandle, std::int32_t* outOverrunFlag);
  int M2ABSR_AlignToByteBoundary(std::int32_t bitstreamHandle);
  int M2ABSR_Initialize();
  int M2ABSR_Finalize();
  int M2ABSR_Create(std::int32_t heapManagerHandle, std::int32_t** outBitstream);
  int M2ABSR_Destroy(std::int32_t* bitstreamHandle);
  int M2ABSR_Reset(std::uint32_t* bitstreamState);
  int M2ABSR_SetBuffer(std::uint32_t* bitstreamState, std::int32_t sourceBuffer, std::int32_t sourceBytes);
  int M2ABSR_IsEndOfBuffer(std::int32_t bitstreamHandle, std::int32_t* outIsEnd);
  int M2AHUFFMAN_Initialize();
  int M2AHUFFMAN_Finalize();
  int M2AIMDCT_Initialize();
  int M2AIMDCT_Finalize();
  std::int32_t M2ADEC_Initialize();
  std::int32_t M2ADEC_Finalize();
  std::int32_t __cdecl M2ADEC_Create(const std::int32_t heapManagerHandle, M2aDecoderContext** outContext);
  std::int32_t __cdecl M2ADEC_Destroy(M2aDecoderContext* context);

  std::int32_t __cdecl M2ADEC_Reset(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_GetStatus(M2aDecoderContext* context, std::int32_t* outStatus);
  std::int32_t __cdecl M2ADEC_GetErrorCode(M2aDecoderContext* context, std::int32_t* outErrorCode);
  std::int32_t __cdecl M2ADEC_Start(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_Stop(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_Process(
    M2aDecoderContext* context,
    std::int32_t sourceAddress,
    std::int32_t sourceBytes,
    std::int32_t* outConsumedBytes
  );
  std::int32_t __cdecl M2ADEC_GetPendingSupply(M2aDecoderContext* context, std::int32_t* outPendingSupply);
  std::int32_t __cdecl M2ADEC_BeginFlush(M2aDecoderContext* context);
  std::int32_t __cdecl M2ADEC_GetNumFramesDecoded(M2aDecoderContext* context, std::int32_t* outFrameCount);
  std::int32_t __cdecl M2ADEC_GetNumSamplesDecoded(M2aDecoderContext* context, std::int32_t* outSampleCount);
  std::int32_t __cdecl M2ADEC_GetProfile(M2aDecoderContext* context, std::int32_t* outProfile);
  std::int32_t __cdecl M2ADEC_GetFrequency(M2aDecoderContext* context, std::int32_t* outFrequency);
  std::int32_t __cdecl M2ADEC_GetNumChannels(M2aDecoderContext* context, std::int32_t* outChannelCount);
  std::int32_t __cdecl M2ADEC_GetChannelConfiguration(M2aDecoderContext* context, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl M2ADEC_GetPcm(M2aDecoderContext* context, std::int32_t channelIndex, std::int32_t destinationAddress);
  std::int32_t __cdecl M2ADEC_GetDownmixedPcm(
    M2aDecoderContext* context,
    std::int32_t outputChannelIndex,
    std::int32_t destinationAddress
  );
  std::int32_t __cdecl M2ADEC_GetSurroundPcm(
    M2aDecoderContext* context,
    std::int32_t outputChannelIndex,
    std::int32_t destinationAddress
  );
  HANDLE __cdecl m2adec_malloc(std::int32_t heapManagerHandle, SIZE_T byteCount);
  HANDLE __cdecl m2adec_free(std::int32_t heapManagerHandle, LPVOID memoryBlock);
  std::int32_t __cdecl m2adec_decode_header(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_header_type(
    const std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outHeaderType
  );
  std::int32_t __cdecl m2adec_get_adif_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_fixed_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_adts_variable_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_crc_check(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_elements(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_sce(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_cpe(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_sce_initialize(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_cpe_initialize(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_ics(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ics_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ms_info(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_get_ms_info8(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_pcm(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_dse(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_fil(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_decode_pce(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_specify_location(M2aDecoderContext* context);
  std::int32_t __cdecl m2adec_find_sync_offset(void* state, std::int32_t* outOffset);
  std::int32_t __cdecl m2adec_convert_to_pcm16(float* sourceSamples, std::int32_t destinationAddress);

  int __cdecl mpabdr_Init();
  int __cdecl mpabdr_Finish();
  int __cdecl MPARBF_SetUsrMallocFunc(std::int32_t allocatorFunctionAddress);
  int __cdecl MPARBF_SetUsrFreeFunc(std::int32_t freeFunctionAddress);
  int __cdecl MPARBF_Create(std::int32_t bufferBytes, std::int32_t* outHandle);
  int __cdecl MPARBF_Destroy(std::int32_t* handleAddress);
  int __cdecl MPARBF_Reset(std::int32_t handleAddress);
  int __cdecl MPARBF_GetDataSize(std::int32_t bitReaderHandle, std::uint32_t* outDataBytes);
  int __cdecl MPARBF_GetFreeSize(std::int32_t bitReaderHandle, std::uint32_t* outFreeBytes);
  int __cdecl MPARBF_ReadData(
    std::int32_t bitReaderHandle,
    char* destinationBytes,
    std::uint32_t byteCount,
    std::uint32_t* outReadBytes
  );
  int __cdecl MPARBF_WriteData(
    std::int32_t bitReaderHandle,
    std::int32_t sourceAddress,
    std::uint32_t byteCount,
    std::uint32_t* outWrittenBytes
  );
  int __cdecl MPARBF_ReturnData(
    std::int32_t bitReaderHandle,
    std::uint32_t returnBytes,
    std::uint32_t* outReturnedBytes
  );
  std::int32_t __cdecl mparbd_Create(MparbdDecoderState** outDecoder);
  std::int32_t __cdecl mparbd_Destroy(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_Reset(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_ExecHndl(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_start_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_prep_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_dechdr_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_decsmpl_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_decend_proc(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPARBD_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  );
  std::int32_t __cdecl mparbd_GetNumSmplDcd(
    MparbdDecoderState* decoder,
    std::int32_t* outDecodedFrameCount,
    std::int32_t* outDecodedBlockCount
  );
  std::int32_t __cdecl MPARBD_GetNumByteDcd(MparbdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl MPARBD_GetSfreq(MparbdDecoderState* decoder, std::int32_t* outSampleRate);
  std::int32_t __cdecl MPARBD_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl mparbd_GetNumChannel(MparbdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl MPARBD_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl mparbd_GetNumBit(MparbdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl MPARBD_EntryErrFunc(std::int32_t callbackFunctionAddress, std::int32_t callbackContext);
  std::int32_t __cdecl MPARBD_SetUsrMallocFunc(std::int32_t allocatorFunctionAddress);
  std::int32_t __cdecl MPARBD_SetUsrFreeFunc(std::int32_t freeFunctionAddress);
  std::int32_t __cdecl MPARBD_Init();
  std::int32_t __cdecl MPARBD_Finish();
  std::int32_t __cdecl MPARBD_Create(MparbdDecoderState** outDecoder);
  std::int32_t __cdecl MPARBD_Destroy(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPARBD_Reset(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPARBD_ExecHndl(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPARBD_GetDecStat(MparbdDecoderState* decoder, std::int32_t* outDecodeState);
  std::int32_t __cdecl MPARBD_GetEndStat(MparbdDecoderState* decoder, std::int32_t* outEndState);
  std::int32_t __cdecl MPARBD_SetEndStat(MparbdDecoderState* decoder, std::int32_t endState);
  std::int32_t __cdecl MPARBD_TermSupply(MparbdDecoderState* decoder);
  std::int32_t __cdecl mparbd_TermSupply(MparbdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_SetCbErr(M2asjdErrorCallback callback, std::int32_t callbackObject);
  std::int32_t __cdecl MPASJD_SetCbDcd(MpasjdDecodeCallback decodeCallback, std::int32_t callbackObject);
  std::int32_t
  __cdecl mpasjd_call_err_func2(const char* functionName, std::int32_t sourceLine, const char* errorMessage, std::int32_t callbackObject);
  std::int32_t __cdecl MPASJD_Init();
  std::int32_t __cdecl mpasjd_Init();
  std::int32_t __cdecl MPASJD_Finish();
  std::int32_t __cdecl mpasjd_Finish();
  std::int32_t __cdecl
  MPASJD_Create(MpasjdDecoderState* decoderStorage, std::int32_t storageBytes, MpasjdDecoderState** outDecoder);
  std::int32_t __cdecl
  mpasjd_Create(MpasjdDecoderState* decoderStorage, std::int32_t storageBytes, MpasjdDecoderState** outDecoder);
  std::int32_t __cdecl mpasjd_set_global_work(std::uint8_t* workBase, std::int32_t workBytes);
  std::int32_t __cdecl mpasjd_malloc_func(std::uint32_t allocationBytes, void** outAllocation);
  std::int32_t __cdecl mpasjd_free_func();
  std::int32_t __cdecl MPASJD_Destroy(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_Destroy(MpasjdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_Reset(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_Reset(MpasjdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_Start(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_Start(MpasjdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_Stop(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_Stop(MpasjdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_GetStat(MpasjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl mpasjd_GetStat(MpasjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl MPASJD_GetNumChannels(MpasjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl mpasjd_GetNumChannels(MpasjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl MPASJD_GetFrequency(MpasjdDecoderState* decoder, std::int32_t* outSampleRate);
  std::int32_t __cdecl mpasjd_GetFrequency(MpasjdDecoderState* decoder, std::int32_t* outSampleRate);
  std::int32_t __cdecl MPASJD_GetNumBits(MpasjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl mpasjd_GetNumBits(MpasjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl MPASJD_GetNumSmplsDcd(MpasjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl mpasjd_GetNumSmplsDcd(MpasjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl MPASJD_GetNumBytesDcd(MpasjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl mpasjd_GetNumBytesDcd(MpasjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl MPASJD_ExecServer();
  std::int32_t __cdecl mpasjd_ExecServer();
  std::int32_t __cdecl MPASJD_ExecHndl(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_ExecHndl(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_input_proc(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_output_proc(MpasjdDecoderState* decoder);
  std::int32_t __cdecl MPASJD_GetIoSj(
    MpasjdDecoderState* decoder,
    M2asjdIoStream** outSourceStream,
    std::int32_t* outOutputStreamCount,
    M2asjdIoStream** outOutputStreams
  );
  std::int32_t __cdecl mpasjd_GetIoSj(
    MpasjdDecoderState* decoder,
    M2asjdIoStream** outSourceStream,
    std::int32_t* outOutputStreamCount,
    M2asjdIoStream** outOutputStreams
  );
  std::int32_t __cdecl MPASJD_SetIoSj(
    MpasjdDecoderState* decoder,
    M2asjdIoStream* sourceStream,
    std::int32_t outputStreamCount,
    M2asjdIoStream** outputStreams
  );
  std::int32_t __cdecl mpasjd_SetIoSj(
    MpasjdDecoderState* decoder,
    M2asjdIoStream* sourceStream,
    std::int32_t outputStreamCount,
    M2asjdIoStream** outputStreams
  );
  std::int32_t __cdecl MPASJD_TermSupply(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_TermSupply(MpasjdDecoderState* decoder);
  std::int32_t __cdecl mpasjd_call_err_func(const char* errorMessage);
  std::int32_t __cdecl mpadcd_GetHdrInfo(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_GetBitAllocInfo(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_GetScfInfo(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_GetSmpl(std::uint32_t* decoderState);
  std::int32_t __cdecl mpadcd_DequantizeSmpl(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_GetPcmSmpl(std::uint32_t* state);
  std::int32_t __cdecl mpadcd_SkipToNextFrm(std::uint32_t* state);
  void* M2AIMDCT_GetWindow(std::int32_t windowSequence, std::int32_t windowShape);
  int M2AIMDCT_TransformShort(float* spectralData, void* previousWindow, void* currentWindow, float* overlapBuffer);
  int M2AIMDCT_TransformLong(float* spectralData, void* previousWindow, void* currentWindow, float* overlapBuffer);
  /**
   * Address: 0x00B255A0 (_m2adec_copy)
   *
   * What it does:
   * Copies one M2A runtime buffer lane and returns copied byte count.
   */
  std::uint32_t m2adec_copy(void* destination, const void* source, std::size_t byteCount);
  std::int32_t __cdecl m2adec_clear(void* destination, std::uint32_t byteCount);
  int M2AHUFFMAN_GetCodebook(int index, std::uintptr_t* outCodebook);
  int M2AHUFFMAN_Decode(int codebookHandle, int bitstreamHandle);
  int M2AHUFFMAN_Unpack(
    std::uint32_t* codebook,
    int packedValue,
    std::int32_t* outValues,
    std::int32_t* outDimension,
    int bitstreamHandle
  );
  int M2AHUFFMAN_GetEscValue(int valuesHandle, int bitstreamHandle);
  extern float m2adec_tns_decode_table[];
  extern std::int32_t m2adec_frequency_table[];
  extern std::int32_t m2adec_num_spectra_per_sfb[];
  extern std::int32_t m2adec_num_spectra_per_sfb8[];
  using XeciErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, const char* errorMessage, std::int32_t errorCode);
  using XeciReadFileCallback = BOOL(
    __cdecl*
  )(HANDLE fileHandle, LPVOID buffer, DWORD bytesToRead, LPDWORD outBytesRead, LPOVERLAPPED overlapped);
  using XeciOpenProbeCallback =
    HANDLE(__cdecl*)(const char* fileName, std::int32_t* outFileSizeLow, std::int32_t* outFileSizeHigh);
  using XeciPathFileSizeProbeCallback = std::int32_t(__cdecl*)(const char* fileName);
  using XeciServerIdleCallback = void(__cdecl*)(std::int32_t callbackObject);

  char* __cdecl xeDirAppendRootDir(char* outputPath, const char* relativeOrAbsolutePath);
  std::int64_t __cdecl xeci_GetFileSizeResolved(const char* fileName);
  std::int32_t __cdecl xeCiGetFileSize(const char* fileName);
  std::int32_t __cdecl xeCiOptionFunc(const void* optionTarget, std::int32_t optionCode);
  std::int32_t __cdecl xeCiSeek(XeciObject* object, std::int32_t offset, std::int32_t originMode);
  std::int32_t __cdecl xeCiTell(const XeciObject* object);
  std::int32_t __cdecl xeCiGetStat(const XeciObject* object);
  std::int32_t __cdecl xeCiGetSctLen(const XeciObject* object);
  std::uint64_t __cdecl xeci_GetFileSizeFromPath(const char* fileName);
  char* __cdecl xeDirAppendRootDirThunk(char* outputPath, const char* relativeOrAbsolutePath);
  std::int32_t __cdecl xeCiGetFileSizeLower(const char* fileName);

  std::int64_t __cdecl xeCiGetFileSizeByHndl(const XeciObject* object);
  BOOL __cdecl xeci_obj_read_from_file(XeciObject* object);
  void __cdecl xeci_obj_update(XeciObject* object);
  std::int32_t __cdecl xeci_has_active_transfer();
  void __cdecl xeCiExecServer();
  HANDLE __cdecl xeci_obj_init(XeciObject* object);
  std::int32_t __cdecl xeci_obj_overlap_cleanup(XeciObject* object);
  std::int32_t __cdecl xeCiGetNumTr(const XeciObject* object);
  void __cdecl xeci_obj_cleanup(XeciObject* object);
  void __cdecl xeci_obj_handle_cleanup(HANDLE objectHandle);
  std::uint64_t __cdecl xeUtyGetFileSizeEx(HANDLE fileHandle);
  std::uint64_t __cdecl xeCiGetNumTrUpper(const XeciObject* object);
  std::int32_t __cdecl xeCiGetNumTrLower(const XeciObject* object);
  std::int32_t __cdecl xeCiGetFileSizeUpper(const XeciObject* object);

  void __cdecl xeci_set_read_mode(
    std::int32_t unusedOptionA,
    std::int32_t unusedOptionB,
    std::int32_t unusedOptionC,
    std::int32_t readMode
  );
  void __cdecl xeci_request_async_abort();
  void wxCiLock_init();
  void wxCiLock_destroy();
  std::int32_t wxCiLock();
  void wxCiUnLock();
  std::int32_t wxCiLock_get_count();
  DWORD xeci_get_chunk_size();
  DWORD __cdecl xeci_set_chunk_size(DWORD chunkSizeBytes);
  BOOL __cdecl xeci_read_file(
    HANDLE fileHandle,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  );
  BOOL __cdecl xeci_read_amt_from_file(
    HANDLE fileHandle,
    LPVOID buffer,
    DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  );
  void __cdecl xeci_lock();
  void __cdecl xeci_unlock();
  std::int32_t xeci_lock_count();
  void __cdecl xeci_lock_n(std::int32_t lockCount);
  std::int32_t __cdecl xeci_obj_update_overlapped(XeciObject* object);
  BOOL SofdecSetTrueThunk(std::int32_t* signalLane);

  /**
   * Address: 0x00B11B50 (xeci_error)
   *
   * What it does:
   * Forwards one XECI error message through `xeci_assert`.
   */
  int __cdecl xeci_error(std::int32_t callbackObject, const char* errorMessage);
  std::int32_t __cdecl M2ASJD_SetCbErr(M2asjdErrorCallback callback, std::int32_t callbackObject);
  std::int32_t __cdecl M2ASJD_Init();
  std::int32_t __cdecl M2ASJD_Finish();
  std::int32_t __cdecl
  M2ASJD_Create(std::int32_t heapManagerHandle, std::int32_t heapManagerOwner, M2asjdDecoderState** outDecoder);
  std::int32_t __cdecl
  m2asjd_Create(std::int32_t heapManagerHandle, std::int32_t heapManagerOwner, M2asjdDecoderState** outDecoder);
  std::int32_t __cdecl M2ASJD_Destroy(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_SetCbDcd(M2asjdDecodeCallback decodeCallback, std::int32_t callbackObject);
  std::int32_t __cdecl m2asjd_default_callback(std::int32_t callbackObject, const char* errorMessage);
  std::int32_t __cdecl m2asjd_Init();
  std::int32_t __cdecl m2asjd_Finish();
  std::int32_t __cdecl M2ASJD_SetCbDcd(M2asjdDecodeCallback decodeCallback, std::int32_t callbackObject);
  std::int32_t __cdecl M2ASJD_Reset(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Reset(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_Start(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Start(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_Stop(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Stop(M2asjdDecoderState* decoder);
  std::int32_t __cdecl M2ASJD_GetStat(M2asjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl m2asjd_GetStat(M2asjdDecoderState* decoder, std::int32_t* outStatus);
  std::int32_t __cdecl M2ASJD_GetNumChannels(M2asjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl m2asjd_GetNumChannels(M2asjdDecoderState* decoder, std::int32_t* outChannelCount);
  std::int32_t __cdecl M2ASJD_GetChannelConfig(M2asjdDecoderState* decoder, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl m2asjd_GetChannelConfig(M2asjdDecoderState* decoder, std::int32_t* outChannelConfiguration);
  std::int32_t __cdecl M2ASJD_GetFrequency(M2asjdDecoderState* decoder, std::int32_t* outFrequency);
  std::int32_t __cdecl m2asjd_GetFrequency(M2asjdDecoderState* decoder, std::int32_t* outFrequency);
  std::int32_t __cdecl M2ASJD_GetNumBits(M2asjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl m2asjd_GetNumBits(M2asjdDecoderState* decoder, std::int32_t* outBitsPerSample);
  std::int32_t __cdecl M2ASJD_GetNumSmplsDcd(M2asjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl m2asjd_GetNumSmplsDcd(M2asjdDecoderState* decoder, std::int32_t* outSampleCount);
  std::int32_t __cdecl M2ASJD_GetNumBytesDcd(M2asjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl m2asjd_GetNumBytesDcd(M2asjdDecoderState* decoder, std::int32_t* outDecodedBytes);
  std::int32_t __cdecl M2ASJD_GetIoSj(
    M2asjdDecoderState* decoder,
    M2asjdIoStream** outSourceStream,
    std::int32_t* outOutputStreamCount,
    M2asjdIoStream** outOutputStreams
  );
  std::int32_t __cdecl m2asjd_GetIoSj(
    M2asjdDecoderState* decoder,
    M2asjdIoStream** outSourceStream,
    std::int32_t* outOutputStreamCount,
    M2asjdIoStream** outOutputStreams
  );
  std::int32_t __cdecl M2ASJD_SetIoSj(
    M2asjdDecoderState* decoder,
    M2asjdIoStream* sourceStream,
    std::int32_t outputStreamCount,
    M2asjdIoStream** outputStreams
  );
  std::int32_t __cdecl m2asjd_SetIoSj(
    M2asjdDecoderState* decoder,
    M2asjdIoStream* sourceStream,
    std::int32_t outputStreamCount,
    M2asjdIoStream** outputStreams
  );
  void* __cdecl m2asjd_malloc(std::int32_t heapManagerHandle, SIZE_T byteCount);
  void __cdecl m2asjd_free(std::int32_t heapManagerHandle, LPVOID memoryBlock);
  std::int32_t __cdecl m2asjd_clear(void* destinationBytes, std::uint32_t byteCount);
  std::uint32_t __cdecl m2asjd_copy(void* destinationBytes, const void* sourceBytes, std::uint32_t byteCount);
  std::int32_t __cdecl M2ASJD_GetDownmixMode(M2asjdDecoderState* decoder, std::int32_t* outDownmixMode);
  std::int32_t __cdecl m2asjd_GetDownmixMode(M2asjdDecoderState* decoder, std::int32_t* outDownmixMode);
  std::int32_t __cdecl M2ASJD_SetDownmixMode(M2asjdDecoderState* decoder, std::int32_t downmixMode);
  std::int32_t __cdecl m2asjd_SetDownmixMode(M2asjdDecoderState* decoder, std::int32_t downmixMode);
  std::int32_t __cdecl M2ASJD_TermSupply(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_TermSupply(M2asjdDecoderState* decoder);
  /**
   * Address: 0x00B0F440 (FUN_00B0F440, _M2ALINK_SetInSj)
   *
   * What it does:
   * Reads current M2ASJD output SJ lanes and rewires input SJ lane.
   */
  std::int32_t __cdecl
  M2ALINK_SetInSj(M2asjdDecoderState* decoder, M2asjdIoStream* sourceStream);
  /**
   * Address: 0x00B0F490 (FUN_00B0F490, _M2ALINK_CallErrFunc)
   *
   * What it does:
   * Bridges one M2A link-layer error message into ADXERR callback lane.
   */
  std::int32_t __cdecl M2ALINK_CallErrFunc(std::int32_t callbackObject, const char* errorMessage);
  std::int32_t __cdecl M2ASJD_ExecServer();
  std::int32_t __cdecl M2ASJD_ExecHndl(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_ExecServer();
  std::int32_t __cdecl m2asjd_ExecHndl(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_input_proc(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_proc(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_stereo(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_surround(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_output_adx(M2asjdDecoderState* decoder);
  std::int32_t __cdecl m2asjd_Destroy(M2asjdDecoderState* decoder);
  /**
   * Address: 0x00B08810 (FUN_00B08810, _SJ_SplitChunk)
   *
   * What it does:
   * Splits one `(address,size)` chunk into head/tail lanes at `splitBytes`.
   */
  SjChunkRange* __cdecl SJ_SplitChunk(
    const SjChunkRange* sourceChunk,
    std::int32_t splitBytes,
    SjChunkRange* outHeadChunk,
    SjChunkRange* outTailChunk
  );
  /**
   * Address: 0x00B08960 (FUN_00B08960, _SJ_MakeTag)
   *
   * What it does:
   * Writes one tag header (`name + 7-hex-length`) into output tag window.
   */
  std::int32_t SJ_MakeTag(moho::MwsfTagWindow* tagWindow, const char* sourceTagName);
  LONG __cdecl xefic_GetInitializeCount();
  void __cdecl xefic_Initialize();
  LONG __cdecl xefic_Finalize();
  LONG XEFIC_Finalize();
  XeficObject* __cdecl xefic_CreateObjectAndBuildQueueSync(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  std::int32_t __cdecl ADXFIC_GetRequiredWorkBytes(const char* rootPath, std::int32_t pathEnumerationMode);
  XeficObject* __cdecl ADXFIC_CreateObjectAndBuildQueueSync(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  XeficObject* __cdecl ADXFIC_CreateObjectForAsyncQueueBuild(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  void __cdecl ADXFIC_CleanupObject(XeficObject* object);
  XeficOpenResultProbeCallback __cdecl
  ADXFIC_SetOpenResultProbeCallback(XeficOpenResultProbeCallback callback, std::int32_t callbackContext);
  std::int32_t __cdecl xefic_CalculateRequiredQueueWorkBytes(const char* rootPath, std::int32_t pathEnumerationMode);
  XeficObject* __cdecl xefic_CreateObjectUnlocked(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  XeficObject* __cdecl xefic_CreateObjectLocked(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  XeficObject* __cdecl xefic_CreateObjectForAsyncQueueBuild(
    const char* rootPath,
    std::int32_t pathEnumerationMode,
    void* externalWorkBuffer,
    std::int32_t externalWorkBufferBytes
  );
  LONG __cdecl xefic_RevalidateQueuedEntryStates(XeficObject* object, const char* rootPath);
  std::int32_t __cdecl xefic_RevalidateQueuedEntryStateCallback(
    const XefindFoundFileInfo* foundFile,
    void* callbackContext
  );
  std::int32_t __cdecl xefic_InitializeObjectWorkBuffer(XeficObject* object);
  void __cdecl xefic_cleanup_obj(XeficObject* object);
  XeficOpenResultProbeCallback __cdecl
  xefic_SetOpenResultProbeCallback(XeficOpenResultProbeCallback callback, std::int32_t callbackContext);
  void __cdecl xefic_CloseObjectQueuedHandles(XeficObject* object);
  std::int32_t __cdecl xefic_CloseQueuedEntryHandleAndReset(XeficQueuedFileEntry* queueEntry, std::int32_t contextValue);
  std::int32_t __cdecl xefic_ReleaseObjectWorkBuffer(XeficObject* object);
  std::int32_t __cdecl xefic_wait_on_obj(XeficObject* object);
  std::int32_t __cdecl xefic_RebuildObjectQueue(XeficObject* object);
  std::int32_t __cdecl xefic_QueueFoundFileForObject(const XefindFoundFileInfo* foundFile, void* callbackContext);
  std::int32_t __cdecl xefic_AccumulateEntryWorkSize(
    const XefindFoundFileInfo* foundFile,
    void* callbackContext
  );
  std::int32_t __cdecl xeci_aligned_str_size(const char* text);
  std::int32_t __cdecl xeci_set_unk1(XefindVisitCallback callback, void* callbackContext);
  std::int32_t __cdecl xefind_Search(char* rootPath, std::int32_t depth, std::uint32_t* counter);
  void __cdecl
  xefic_ForEachQueuedEntryOnObjectLocked(XeficObject* object, XeficQueueVisitor visitor, std::int32_t contextValue);
  std::int32_t __cdecl xefic_GetQueuedEntryCount(const XeficObject* object);
  XeficQueuedFileEntry* __cdecl xefic_obj_pop(XeficObject* object);
  XeficQueuedFileEntry* __cdecl xefic_FindQueuedFileEntryByPathLocked(const char* rootedFileName);
  void XEFIC_Initialize();
  DWORD __stdcall xeci_thread_server(LPVOID threadParameter);

  std::int32_t __cdecl SKG_GenerateKeyForEncoder(
    const char* sourceBytes,
    std::int32_t sourceLength,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  );
  std::int32_t __cdecl SKG_Init_also();
  std::int32_t __cdecl SKG_Finish_also();
  std::int32_t __cdecl ADXSJE_Init();
  std::int32_t __cdecl ADXSJE_Finish();
  AdxStreamJoinEncoderState* __cdecl ADXSJE_Create(
    std::int32_t channelCount,
    moho::SofdecSjSupplyHandle* const* inputSjHandles,
    moho::SofdecSjSupplyHandle* outputSjHandle
  );
  void __cdecl ADXSJE_Destroy(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl ADXSJE_Start(AdxStreamJoinEncoderState* encoder);
  AdxStreamJoinEncoderState* __cdecl ADXSJE_Stop(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl ADXSJE_SetSfreq(AdxStreamJoinEncoderState* encoder, std::int32_t sampleRate);
  std::int32_t __cdecl ADXSJE_SetHdInfoSize(AdxStreamJoinEncoderState* encoder, std::int32_t headerInfoSizeBytes);
  std::int32_t __cdecl ADXSJE_SetNumChan(AdxStreamJoinEncoderState* encoder, std::int32_t channelCount);
  std::int32_t __cdecl ADXSJE_SetTotalNumSmpl(AdxStreamJoinEncoderState* encoder, std::int32_t totalSampleCount);
  std::int32_t __cdecl ADXSJE_SetOutBps(AdxStreamJoinEncoderState* encoder, std::int32_t outputBitsPerSample);
  std::int32_t __cdecl ADXSJE_SetBlkSmpl(AdxStreamJoinEncoderState* encoder, std::int32_t blockSampleCount);
  std::int32_t __cdecl ADXSJE_SetBlkLen(AdxStreamJoinEncoderState* encoder, std::int32_t blockLengthBytes);
  std::int32_t __cdecl ADXSJE_GetInfo(
    std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outSampleBits,
    std::int32_t* outChannels,
    std::int32_t* outBlockSamples,
    std::int32_t* outSampleRate
  );
  std::int32_t __cdecl ADXSJE_CalcLpInfo(
    std::int32_t channelCount,
    std::int32_t currentSampleCount,
    std::int32_t loopEndSampleCount,
    std::int32_t* outHeaderInfoSizeBytes,
    std::int32_t* outPaddedSampleCount,
    std::int32_t* outLoopStartOffset,
    std::int32_t* outLoopEndOffset
  );
  std::int32_t __cdecl
  adxsje_nsmpl_to_ofst(std::int32_t channelCount, std::int32_t headerInfoSizeBytes, std::int32_t sampleCount);
  std::int16_t __cdecl ADXSJE_GetVersion();
  char* __cdecl ADXSJE_GetVerStr();
  std::int32_t __cdecl ADXSJE_SetCof(AdxStreamJoinEncoderState* encoder, std::int32_t predictorPreset);
  std::int32_t __cdecl ADXSJE_SetNumLoop(AdxStreamJoinEncoderState* encoder, std::int32_t loopCount);
  std::int32_t __cdecl ADXSJE_SetLpInsNsmpl(AdxStreamJoinEncoderState* encoder, std::int32_t loopInsertedSamples);
  std::int32_t __cdecl ADXSJE_SetLpStartPos(AdxStreamJoinEncoderState* encoder, std::int32_t loopStartSamplePosition);
  std::int32_t __cdecl ADXSJE_SetLpStartOfst(AdxStreamJoinEncoderState* encoder, std::int32_t loopStartByteOffset);
  std::int32_t __cdecl ADXSJE_SetLpEndPos(AdxStreamJoinEncoderState* encoder, std::int32_t loopEndSamplePosition);
  std::int32_t __cdecl ADXSJE_SetLpEndOfst(AdxStreamJoinEncoderState* encoder, std::int32_t loopEndByteOffset);
  AdxStreamJoinEncoderState* __cdecl ADXSJE_SetAinfOutputVol(
    AdxStreamJoinEncoderState* encoder,
    std::int16_t outputVolume
  );
  AdxStreamJoinEncoderState* __cdecl ADXSJE_SetAinfOutputPan(
    AdxStreamJoinEncoderState* encoder,
    std::int32_t channelIndex,
    std::int16_t outputPan
  );
  std::uint8_t* __cdecl ADXSJE_SetAinfDataId(AdxStreamJoinEncoderState* encoder, const char* sourceDataIdBytes);
  std::uint8_t* __cdecl ADXSJE_SetAinfDataIdMem(
    AdxStreamJoinEncoderState* encoder,
    const std::uint8_t (*sourceDataIdBytes)[0x10]
  );
  std::uint8_t* __cdecl ADXSJE_ClearAinf(AdxStreamJoinEncoderState* encoder);
  std::int8_t __cdecl
  ADXSJE_SetCommonInf(AdxStreamJoinEncoderState* encoder, std::int32_t commonInfoDataOffset, std::int32_t commonInfoDataBytes);
  std::int32_t __cdecl ADXSJE_SetConfigSfa(
    AdxStreamJoinEncoderState* encoder,
    std::int32_t channelCount,
    std::int32_t sampleRate,
    std::int32_t totalSampleCount
  );
  AdxStreamJoinEncoderState* __cdecl
  ADXSJE_SetExtStringForEncoder(AdxStreamJoinEncoderState* encoder, const char* extString);
  std::int32_t __cdecl ADXSJE_GetEncDtLen(const AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl ADXSJE_GetEncNumSmpl(const AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl ADXSJE_SetEncPos(AdxStreamJoinEncoderState* encoder, std::int32_t encodedSamplePosition);
  std::int32_t __cdecl ADXSJE_GetEncPos(const AdxStreamJoinEncoderState* encoder);
  std::uint32_t __cdecl ADXSJE_SetInSj(
    AdxStreamJoinEncoderState* encoder,
    std::uint32_t inputLaneIndex,
    moho::SofdecSjSupplyHandle* inputSjHandle
  );
  moho::SofdecSjSupplyHandle* __cdecl
  ADXSJE_SetOutSj(AdxStreamJoinEncoderState* encoder, moho::SofdecSjSupplyHandle* outputSjHandle);
  std::int32_t __cdecl adxsje_encode_prep(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl adxsje_encode_exec(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl ADXSJE_ExecHndl(AdxStreamJoinEncoderState* encoder);
  std::int32_t ADXSJE_ExecServer();
  void ADXSJE_NoOpStateCallback();
  void ADXSJE_NoOpSupplyCallback();

  std::int32_t __cdecl
  adxsje_output_header(AdxStreamJoinEncoderState* encoder, moho::SofdecSjSupplyHandle* outputSjHandle);
  std::int32_t __cdecl adxsje_encode_data(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl adxsje_write_end_code(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl adxsje_write68(
    const void* sourceBytes,
    std::int32_t bytesPerElement,
    std::int32_t elementCount,
    moho::SofdecSjSupplyHandle* outputSjHandle
  );
  std::int32_t __cdecl adxsje_encode_blk(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl adxsje_output_sdata(AdxStreamJoinEncoderState* encoder);
  std::int32_t __cdecl adxsje_get_pcm_data(
    AdxStreamJoinEncoderState* encoder,
    std::int32_t encodedSamplePosition,
    std::int32_t requestedSampleCount,
    std::int16_t** channelSamplePlanes
  );
  std::int32_t __cdecl adxsje_calc_rsig(AdxStreamJoinEncoderState* encoder, std::int32_t channelIndex);
  std::int32_t __cdecl adxsje_set_rsig(AdxStreamJoinEncoderState* encoder, std::int32_t channelIndex);
  char* __cdecl iirflt_create();
  std::int32_t __cdecl iirflt_destroy(std::int32_t iirFilterHandle);
  std::int32_t __cdecl
  iirflt_set_coef(std::int32_t iirFilterHandle, std::int16_t coefficient0, std::int16_t coefficient1);
  std::int32_t __cdecl
  iirflt_set_delay(std::int32_t iirFilterHandle, std::int16_t delay0, std::int16_t delay1);
  std::int16_t __cdecl
  iirflt_get_delay(std::int32_t iirFilterHandle, std::int16_t* outDelay0, std::int16_t* outDelay1);
  std::int16_t __cdecl iirflt_put_sig(std::int32_t iirFilterHandle, std::int16_t sample);
  std::int32_t __cdecl
  pflt_set_coef(std::int32_t filterHandle, std::int16_t coefficient0, std::int16_t coefficient1);
  std::int32_t __cdecl pflt_set_delay(std::int32_t filterHandle, std::int16_t delay0, std::int16_t delay1);
  std::int32_t __cdecl pflt_put_sig(std::int32_t filterHandle, std::int32_t sampleIndex, std::int16_t sample);
  std::int32_t __cdecl pflt_calc_gain(std::int32_t filterHandle);
  std::int16_t __cdecl pflt_get_rsig(std::int32_t filterHandle, std::int32_t sampleIndex);
  std::int8_t __cdecl pflt_get_rsig_q(std::int32_t filterHandle, std::int32_t sampleIndex);
  std::int8_t __cdecl pflt_set_rsig_q(std::int32_t filterHandle, std::int32_t sampleIndex, std::int8_t value);
  std::int32_t __cdecl ADX_GetCoefficient(
    std::int32_t coefficientIndex,
    std::int32_t sampleRate,
    std::int16_t* outCoefficient0,
    std::int16_t* outCoefficient1
  );
  std::int32_t __cdecl ADX_CalcHdrInfoLen(
    std::int32_t loopInsertedSamples,
    std::int32_t loopCount,
    std::int32_t channelCount,
    std::int32_t bytesPerSample
  );
  void __cdecl ADXCRS_Lock();
  void __cdecl ADXCRS_Unlock();
  std::int32_t __cdecl pflt_create(std::int32_t blockSampleCount);
  void __cdecl pflt_destroy(std::int32_t filterHandle);
  std::int32_t __cdecl pflt_calc_coef(std::int32_t filterHandle, std::int32_t preset, std::int32_t sampleRate);
  std::int32_t __cdecl iirflt_init();

  std::uint8_t* adxb_ResetAinf(moho::AdxBitstreamDecoderState* decoder);
  int ADXB_CheckSpsd(const std::uint8_t* headerBytes);
  int ADXB_CheckWav(const std::uint8_t* headerBytes);
  int ADXB_CheckAiff(const std::uint8_t* headerBytes);
  int ADXB_CheckAu(const std::uint8_t* headerBytes);
  int ADXB_CheckMpa(const std::uint8_t* headerBytes);
  int ADXB_CheckM2a(const std::uint8_t* headerBytes);

  int ADXB_DecodeHeaderSpsd(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderWav(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderAiff(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderAu(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderMpa(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  int ADXB_DecodeHeaderM2a(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize);
  std::int32_t ADXB_SetMpaInSj(moho::AdxBitstreamDecoderState* decoder);
  std::uint32_t ADXB_SetMpaDecSmpl(moho::AdxBitstreamDecoderState* decoder, std::int32_t maxDecodeSamples);
  std::int32_t ADXB_SetM2aInSj(moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXB_SetM2aDecSmpl(moho::AdxBitstreamDecoderState* decoder, std::int32_t maxDecodeSamples);
  std::int32_t ADXB_MpaTermSupply(moho::AdxBitstreamDecoderState* decoder);
  std::int32_t ADXB_M2aTermSupply(moho::AdxBitstreamDecoderState* decoder);
  std::int32_t __cdecl ADXB_ExecOneWav(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneSpsd(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAiff(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAu(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneAhx(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneMpa(std::int32_t decoderAddress);
  std::int32_t __cdecl ADXB_ExecOneM2a(std::int32_t decoderAddress);
  struct SflibErrorInfo;
  struct SflibLibWorkRuntime;
  using SflibErrorCallback = std::int32_t(__cdecl*)(std::int32_t callbackObject, std::int32_t errorCode);
  std::int32_t SFHDS_Init();
  std::int32_t SFHDS_Finish();
  std::int32_t SFPLY_Init();
  std::int32_t sfply_ChkCondDfl();
  std::int32_t sfply_StatStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatPrep(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustPrepEnd(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_FixAvPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustSyncMode(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_AdjustEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatStby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatPlay(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_StatFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsStartSync(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ChkBpa(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsBpaOn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsBpaOff(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_VbIn();
  void SFD_VbOut();
  std::int32_t sfply_ExecOneSub(std::int32_t workctrlAddress);
  std::int32_t sfply_TrExecServer(std::int32_t workctrlAddress);
  std::int32_t SFSEE_ExecServer(std::int32_t workctrlAddress);
  std::int32_t SFSEE_FixAvPlay(std::int32_t workctrlAddress, std::int32_t condition5State, std::int32_t condition6State);
  std::int32_t sfply_ExecOne(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ChkFin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsEtime(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsEtrg(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsStagnant(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_IsPlayTimeAutoStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_Fin(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  moho::SofdecSfdWorkctrlSubobj* sfply_Create(const moho::SfplyCreateParams* createParams, std::int32_t createContext);
  std::int32_t sfply_ChkCrePara(const moho::SfplyCreateParams* createParams);
  std::int32_t sfply_SearchFreeHn();
  std::int32_t sfply_InitMvInf(moho::SfplyMovieInfo* movieInfo);
  std::int32_t sfply_InitPlyInf(moho::SfplyPlaybackInfo* playbackInfo);
  moho::SfplyFlowCount* sfply_InitFlowCnt(moho::SfplyFlowCount* flowCount);
  std::int32_t sfply_InitTmrInf(moho::SfplyTimerInfo* timerInfo);
  std::int32_t SFPLY_AddDecPic(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t decodedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t SFPLY_AddSkipPic(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t skippedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t sfply_TrCreate(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_TrDestroy(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_Start(void* sfdHandle);
  std::int32_t sfply_Start(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_TrStart(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFD_Stop(void* sfdHandle);
  std::int32_t SFPLY_Stop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFPLY_SetResetFlg(std::int32_t enabled);
  std::int32_t SFPLY_GetResetFlg();
  std::int32_t sfply_TrStop(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_ResetHn(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  moho::SofdecSfdWorkctrlSubobj* sfply_InitHn(const moho::SfplyCreateParams* createParams, std::int32_t createContext);
  std::int32_t sfply_IsAnyoneTerm(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_EnoughViData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t sfply_EnoughAiData(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  void SFPLY_MeasureFps(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  /**
   * Address: 0x00ADD950 (FUN_00ADD950, _SFPL2_Pause)
   *
   * What it does:
   * Applies pause transition mode against per-handle pause-depth/state lanes.
   */
  std::int32_t SFPL2_Pause(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj, std::int32_t paused);
  /**
   * Address: 0x00ADDA40 (FUN_00ADDA40, _SFPL2_Standby)
   *
   * What it does:
   * Switches one handle to standby phase lane.
   */
  std::int32_t SFPL2_Standby(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  std::int32_t SFHDS_FinishFhd(void* fileHeaderState);
  void SFBUF_DestroySj(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  /**
   * Address: 0x00AEADC0 (FUN_00AEADC0, _SFTMR_InitTsum)
   *
   * What it does:
   * Initializes one timer-summary lane to neutral sum/min/max/count defaults.
   */
  moho::SfplyTimerSummary* SFTMR_InitTsum(moho::SfplyTimerSummary* timerSummary);
  /**
   * Address: 0x00AEADF0 (FUN_00AEADF0, _SFTMR_AddTsum)
   *
   * What it does:
   * Adds one signed 64-bit sample into one timer-summary lane.
   */
  void* SFTMR_AddTsum(void* timerSummaryLane, std::int32_t deltaLowWord, std::int32_t deltaHighWord);
  /**
   * Address: 0x00AEACF0 (FUN_00AEACF0, _SFTMR_GetTmr)
   *
   * What it does:
   * Returns current timer ticks while refreshing global timer-unit cache.
   */
  std::int64_t SFTMR_GetTmr();
  /**
   * Address: 0x00AEAD90 (FUN_00AEAD90, _SFTMR_GetTmrUnit)
   *
   * What it does:
   * Returns cached timer-unit ticks, refreshing cache on first read.
   */
  std::int64_t SFTMR_GetTmrUnit();
  std::int32_t SFTIM_VbIn();
  /**
   * Address: 0x00ADAF30 (FUN_00ADAF30, _SFTIM_GetAudioStartSample)
   *
   * What it does:
   * Converts ADXT start PTS (90 kHz) to sample index at requested sample rate.
   */
  std::int32_t SFTIM_GetAudioStartSample(void* adxtRuntime, std::int32_t audioSampleRate);
  /**
   * Address: 0x00ADAF90 (FUN_00ADAF90, _SFTIM_GetVideoStartSample)
   *
   * What it does:
   * Converts ADXT video-start timing lanes to sample index and reports whether
   * explicit video-start timing was used.
   */
  std::int32_t SFTIM_GetVideoStartSample(void* adxtRuntime, std::int32_t audioSampleRate, std::int32_t* outHasExplicitStartTime);
  /**
   * Address: 0x00ADAFF0 (FUN_00ADAFF0, _SFTIM_SetStartTime)
   *
   * What it does:
   * Stores one per-handle playback start-time pair.
   */
  std::int32_t
  SFTIM_SetStartTime(std::int32_t workctrlAddress, std::int32_t startTimeMajor, std::int32_t startTimeMinor);
  void SFTIM_GetTime(std::int32_t workctrlAddress, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  /**
   * Address: 0x00ADBEC0 (FUN_00ADBEC0, _SFTIM_SetSpeed)
   *
   * What it does:
   * Stores one per-handle timer speed rational lane.
   */
  std::int32_t SFTIM_SetSpeed(std::int32_t workctrlAddress, std::int32_t speedRational);
  /**
   * Address: 0x00ADBED0 (FUN_00ADBED0, _SFTIM_GetSpeed)
   *
   * What it does:
   * Returns one per-handle timer speed rational lane.
   */
  std::int32_t SFTIM_GetSpeed(std::int32_t workctrlAddress);
  std::int32_t SFTIM_GetTimeSub(
    moho::SofdecSfdWorkctrlSubobj* workctrlSubobj,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t SFTIM_IsStagnant(moho::SofdecSfdWorkctrlSubobj* workctrlSubobj);
  /**
   * Address: 0x00ADB3D0 (FUN_00ADB3D0, _SFD_CmpTime)
   *
   * What it does:
   * Thin thunk that forwards one time-pair compare to `UTY_CmpTime`.
   */
  std::int32_t SFD_CmpTime(
    std::int32_t lhsIntegerPart,
    std::int32_t lhsFractionalPart,
    std::int32_t rhsIntegerPart,
    std::int32_t rhsFractionalPart
  );
  std::int32_t CRICFG_Read(const char* key, std::int32_t* outValue);
  /**
   * Address: 0x00AE6F90 (FUN_00AE6F90, _set_unit)
   *
   * What it does:
   * Stores one global timer-unit lane and returns its low 32-bit value.
   */
  std::int32_t set_unit(std::int64_t frequencyTicks);
  /**
   * Address: 0x00AE6E20 (FUN_00AE6E20, _UTY_GetTmr)
   *
   * What it does:
   * Reads high-resolution counter ticks when timer init/channel state is valid.
   */
  std::int64_t UTY_GetTmr();
  /**
   * Address: 0x00AE6E00 (FUN_00AE6E00, _UTY_FinishTmr)
   *
   * What it does:
   * Decrements timer init-reference count and clamps global count at zero.
   */
  std::int32_t UTY_FinishTmr();
  /**
   * Address: 0x00AE6EB0 (FUN_00AE6EB0, _UTY_GetTmrUnit)
   *
   * What it does:
   * Returns the global timer-unit lane.
   */
  std::int64_t UTY_GetTmrUnit();
  /**
   * Address: 0x00AE6E60 (FUN_00AE6E60, _UTY_IsTmrVoid)
   *
   * What it does:
   * Returns `1` when timer-unit lane is `0` or `1`; otherwise returns `0`.
   */
  std::int32_t UTY_IsTmrVoid();
  /**
   * Address: 0x00AE6FB0 (FUN_00AE6FB0, _UTY_InitTsum)
   *
   * What it does:
   * Initializes one timer-summary lane to neutral sum/min/max/count defaults.
   */
  moho::SfplyTimerSummary* UTY_InitTsum(moho::SfplyTimerSummary* timerSummary);
  std::int32_t UTY_MulDiv(std::int32_t lhs, std::int32_t rhs, std::int32_t divisor);
  void ADXCRS_Lock();
  void ADXCRS_Unlock();
  std::int32_t sflib_InitLibWork(const moho::MwsfdInitSfdParams* initParams);
  void sflib_InitBaseLib();
  void sflib_InitSub();
  void sflib_InitCs();
  SflibErrorInfo* sflib_InitErr(SflibErrorInfo* errInfo);
  SflibErrorInfo*
  sflib_SetErrFnSub(SflibErrorInfo* errInfo, SflibErrorCallback callback, std::int32_t callbackObject);
  SflibLibWorkRuntime* sflib_InitResetPara(SflibLibWorkRuntime* libWork);
  /**
   * Address: 0x00ADA9C0 (FUN_00ADA9C0, _SFTIM_Init)
   *
   * What it does:
   * Initializes global timer lanes and stores caller timer-version tag.
   */
  void SFTIM_Init(void* timerState, std::int32_t versionTag);
  /**
   * Address: 0x00ADA9E0 (FUN_00ADA9E0, _SFTIM_Finish)
   *
   * What it does:
   * Finalizes global timer runtime (no-op in this build).
   */
  void SFTIM_Finish(void* timerState);
  void sflib_FinishCs();
  std::int32_t sflib_FinishSub();
  std::int32_t sflib_FinishBaseLib();
  extern std::int32_t(__cdecl* ahxsetsjifunc)(void* ahxDecoderHandle);
  extern void(__cdecl* ahxsetdecsmplfunc)(void* ahxDecoderHandle, std::int32_t maxDecodeSamples);
  extern std::int32_t(__cdecl* ahxexecfunc)();
  extern std::int32_t(__cdecl* ahxtermsupplyfunc)(void* ahxDecoderHandle);
  extern std::int32_t(__cdecl* mpaexecfunc)();
  extern std::int32_t(__cdecl* mpatermsupplyfunc)(void* mpaDecoderHandle);
  extern std::int32_t(__cdecl* mpasetsjifunc)(void* mpaDecoderHandle);
  extern std::int32_t(__cdecl* m2aexecfunc)();
  extern std::int32_t(__cdecl* m2asetsjifunc)(void* m2aDecoderHandle);
  extern std::int32_t(__cdecl* m2atermsupplyfunc)(void* m2aDecoderHandle);
  extern std::int32_t adxt_q12_mix_table[];

  extern void(__cdecl* ahxsetextfunc)(void* ahxDecoderHandle, const std::int16_t* extParams);
  extern M2asjdDecodeCallback m2asjd_dcd_func;
  extern std::int32_t m2asjd_dcd_obj;
  extern M2asjdDecoderState* m2asjd_entry;
  extern HANDLE m2asjd_global_heap;
  extern LONG m2asjd_init_count;
  extern CRITICAL_SECTION m2asjd_crs;
  extern CRITICAL_SECTION mpasjd_crs;
  extern MpasjdDecodeCallback mpasjd_dcd_func;
  extern std::int32_t mpasjd_dcd_obj;
  extern MpasjdDecoderState* mpasjd_entry;
  extern std::int32_t mpasjd_init_count;
  extern std::uint8_t* mpasjd_global_work;
  extern std::int32_t mpasjd_global_wksize;
  extern M2asjdErrorCallback mpasjd_err_func;
  extern std::int32_t mpasjd_err_obj;
  extern M2asjdErrorCallback m2asjd_err_func;
  extern std::int32_t m2asjd_err_obj;
  extern CRITICAL_SECTION xefic_lock_obj;
  extern XeficObject xefic_crs[16];
  extern LONG adxfic_init_count;
  extern LONG xefic_initialize_count;
  extern void(__cdecl* xefic_work_complete_callback)(XeficObject* object);
  extern XeficObjectCleanupCallback xefic_object_cleanup_callback;
  extern LONG xefic_search_guard;
  extern XeficOpenResultProbeCallback xefic_open_result_probe_callback;
  extern std::int32_t xefic_open_result_probe_context;
  extern HANDLE xeci_thread;
  extern std::int32_t xeci_is_done;
  extern std::int32_t xeci_old_thread_prio;
  extern XeciErrorCallback xeci_err_func;
  extern std::int32_t xeci_err_obj;
  extern XeciOpenProbeCallback xeci_open_probe_callback;
  extern XeciReadFileCallback wxCiLock_fn;
  extern LONG wxCiLock_inited;
  extern std::int32_t wxCiLock_count;
  extern CRITICAL_SECTION wxCiLock_obj;
  extern std::int32_t xeci_read_file_mode;
  extern std::int32_t xeci_obj_currently_reading;
  extern std::int32_t xeci_async_abort_requested;
  extern DWORD xeci_chunk_size;
  extern std::int32_t adxstmf_execsvr_flg;
  extern std::int32_t adxstmf_num_rtry;
  extern std::int32_t adxstmf_invalid_source_handle_count;
  extern char wxfic_cache_file[0x140];
  extern XeciObject xedir_work[80];
  extern CvFsUserErrorBridgeFn cvfs_errfn;
  extern std::int32_t cvfs_errobj;
  extern MfciHandle mfci_obj[80];
  extern CvFsUserErrorBridgeFn mfci_err_func;
  extern std::int32_t mfci_err_obj;
  extern char mfci_err_str[0x100];
  extern CvFsDeviceInterfaceView mfci_vtbl;
  extern CvFsDeviceInterfaceView xeci_vtbl;
  extern std::int32_t cvfs_init_cnt;
  extern std::array<char, MAX_PATH> gXeDirRootDirectory;
  extern moho::AdxmErrorCallback crierr_callback_func;
  extern std::int32_t crierr_callback_obj;
  extern char crierr_err_msg[0x100];
  extern std::int32_t mwsfd_init_flag;
  extern std::int32_t mwg_vcnt;
  extern std::int32_t mwsfd_vsync_dispatch_count;

  std::int16_t adxb_def_k0 = 0;
  std::int16_t adxb_def_km = 0;
  std::int16_t adxb_def_ka = 0;
  std::int32_t adxb_dec_err_mode = 0;
  std::int32_t adx_decode_output_mono_flag = 0;
  std::int32_t adxt_output_mono_flag = 0;
  std::int32_t mwg_vcnt = 0;
  std::int32_t mwsfd_vsync_dispatch_count = 0;
  std::int32_t adxt_tsvr_enter_cnt = 0;
  std::int32_t adxsje_init_cnt = 0;
  std::int32_t adxsmp_init_cnt = 0;
  std::int32_t skg_init_count_also = 0;
  std::int32_t skg_init_count = 0;
  std::int32_t AdxGainDataMax = 0x1000;
  AdxsjeIirFilterState adxsje_prdflt_obj[kAdxsjePredictorFilterSlotCount]{};
  AdxsjePredictorFilterState adxsje_predictor_filter_pool[kAdxsjePredictorFilterSlotCount]{};
  AdxStreamJoinEncoderState adxsje_obj[kAdxsjeObjectCount]{};
  std::int32_t adxt_dbg_sj_backlog = 0;
  std::int32_t adxt_dbg_sj_channels = 0;
  moho::AdxBitstreamDecoderState adxb_obj[32]{};
  AdxampRuntimeState adxamp_obj[kAdxsjdObjectCount]{};
  moho::AdxrnaTimingState adxrna_timing_pool[32]{};
  std::int32_t(__cdecl* adxrna_GetTime)() = nullptr;
  using AdxtCodecDetachCallback = std::int32_t(__cdecl*)(void* adxtRuntime);
  using AdxtCodecDetachThunkCallback = std::int32_t(__cdecl*)();
  using AdxtCodecStopCallback = void(__cdecl*)(void* runtimeHandle);
  AdxtCodecDetachThunkCallback ahxdetachfunc = nullptr;
  AdxtCodecDetachCallback mpadetachfunc = nullptr;
  AdxtCodecDetachCallback m2adetachfunc = nullptr;
  AdxtCodecStopCallback mpastopfunc = nullptr;
  AdxtCodecStopCallback m2astopfunc = nullptr;
  AdxtEndDecodeInfoCallback adxt_enddecinfo_cbfn = nullptr;
  std::int32_t adxt_dbg_rna_ndata = 0;
  std::int32_t(__cdecl* mpaexecfunc)() = nullptr;
  std::int32_t(__cdecl* mpatermsupplyfunc)(void* mpaDecoderHandle) = nullptr;
  std::int32_t(__cdecl* mpasetsjifunc)(void* mpaDecoderHandle) = nullptr;
  std::int32_t(__cdecl* m2aexecfunc)() = nullptr;
  std::int32_t(__cdecl* m2asetsjifunc)(void* m2aDecoderHandle) = nullptr;
  std::int32_t(__cdecl* m2atermsupplyfunc)(void* m2aDecoderHandle) = nullptr;
  extern std::int16_t skg_prim_tbl[1024];
  MparbdErrorCallback mparbd_err_func = nullptr;
  std::int32_t mparbd_err_param = 0;
  MparbdUserMallocCallback mparbd_malloc_func = nullptr;
  MparbdUserFreeCallback mparbd_free_func = nullptr;
  MparbdUserMallocCallback mparbf_malloc_func = nullptr;
  MparbdUserFreeCallback mparbf_free_func = nullptr;
  HANDLE m2adec_global_heap = nullptr;
  std::int32_t mparbd_init_count = 0;
  MparbdDecoderState* mparbd_entry = nullptr;
  MpasjdDecodeCallback mpasjd_dcd_func = nullptr;
  std::int32_t mpasjd_dcd_obj = 0;
  MpasjdDecoderState* mpasjd_entry = nullptr;
  std::int32_t mpasjd_init_count = 0;
  std::uint8_t* mpasjd_global_work = nullptr;
  std::int32_t mpasjd_global_wksize = 0;
  M2asjdDecodeCallback m2asjd_dcd_func = nullptr;
  std::int32_t m2asjd_dcd_obj = 0;
  M2asjdDecoderState* m2asjd_entry = nullptr;
  HANDLE m2asjd_global_heap = nullptr;
  LONG m2asjd_init_count = 0;
  CRITICAL_SECTION m2asjd_crs{};
  CRITICAL_SECTION mpasjd_crs{};
  M2asjdErrorCallback mpasjd_err_func = nullptr;
  std::int32_t mpasjd_err_obj = 0;
  M2asjdErrorCallback m2asjd_err_func = nullptr;
  std::int32_t m2asjd_err_obj = 0;
  CRITICAL_SECTION xefic_lock_obj{};
  XeficObject xefic_crs[16]{};
  LONG adxfic_init_count = 0;
  LONG xefic_initialize_count = 0;
  void(__cdecl* xefic_work_complete_callback)(XeficObject* object) = nullptr;
  XeciErrorCallback xeci_err_func = nullptr;
  std::int32_t xeci_err_obj = 0;
  XeciOpenProbeCallback xeci_open_probe_callback = nullptr;
  XeciPathFileSizeProbeCallback xeci_file_size_probe_callback = nullptr;
  XeciServerIdleCallback xeci_server_idle_callback = nullptr;
  XeciReadFileCallback wxCiLock_fn = nullptr;
  LONG wxCiLock_inited = 0;
  std::int32_t wxCiLock_count = 0;
  CRITICAL_SECTION wxCiLock_obj{};
  std::int32_t xeci_read_file_mode = 0;
  std::int32_t xeci_obj_currently_reading = 0;
  std::int32_t xeci_async_abort_requested = 0;
  DWORD xeci_chunk_size = 0x8000u;
  std::int32_t adxstmf_execsvr_flg = 0;
  std::int32_t adxstmf_num_rtry = 0;
  std::int32_t adxstmf_invalid_source_handle_count = 0;
  XeficObjectCleanupCallback xefic_object_cleanup_callback = nullptr;
  LONG xefic_search_guard = 0;
  XeficOpenResultProbeCallback xefic_open_result_probe_callback = nullptr;
  std::int32_t xefic_open_result_probe_context = 0;
  char wxfic_cache_file[0x140]{};
  XeciObject xedir_work[80]{};
  CvFsUserErrorBridgeFn cvfs_errfn = nullptr;
  std::int32_t cvfs_errobj = 0;
  moho::AdxmErrorCallback crierr_callback_func = nullptr;
  std::int32_t crierr_callback_obj = 0;
  char crierr_err_msg[0x100]{};
  MfciHandle mfci_obj[80]{};
  CvFsUserErrorBridgeFn mfci_err_func = nullptr;
  std::int32_t mfci_err_obj = 0;
  char mfci_err_str[0x100]{};
  CvFsDeviceInterfaceView mfci_vtbl{};
  CvFsDeviceInterfaceView xeci_vtbl{};
  std::int32_t cvfs_init_cnt = 0;
  float m2asjd_downmix_table[4] = {0.5f, 0.35355338f, 0.25f, 0.0f};
  float m2asjd_downmix_buffer[1024]{};

  std::int32_t gSofdecSjRingBufferInitCount = 0;
  std::int32_t gSofdecSjMemoryInitCount = 0;
  std::int32_t gSofdecSjUnifyInitCount = 0;
  moho::SofdecSjRingBufferHandle gSofdecSjRingBufferPool[0x300]{};
  moho::SofdecSjMemoryHandle gSofdecSjMemoryPool[0x60]{};
  moho::SofdecSjUnifyHandle gSofdecSjUnifyPool[0xC0]{};
  std::int32_t gSofdecSjRingBufferVtableTag = 0;
  std::int32_t gSofdecSjMemoryVtableTag = 0;
  std::int32_t gSofdecSjUnifyVtableTag = 0;
  std::int32_t gSofdecSjRingBufferUuidTag = 0;
  std::int32_t gSofdecSjMemoryUuidTag = 0;
  std::int32_t gSofdecSjUnifyUuidTag = 0;
  std::int32_t gSfbufSjRingBufferUuid = 0;
  std::int32_t gSfbufSjMemoryUuid = 0;
  std::int32_t gAdxpcDvdErrorReportingEnabled = 0;
  moho::SofdecSoundPort gSofdecSoundPortPool[32]{};
  std::array<std::int16_t, 0x10000> gSofdecStereoPanScratch{};
  IDirectSound* gSofdecDirectSound = nullptr;
  IDirectSoundBuffer* gSofdecRestoreProbeBuffer = nullptr;
  std::int32_t gSofdecDirectSoundVersionTag = 0;
  std::int32_t gSofdecMonoRoutingMode = 0;
  std::int32_t gSofdecOpenPortCount = 0;
  std::int32_t gSofdecFrequencyMode = 0;
  std::int32_t gSofdecGlobalFocusMode = 0;
  std::int32_t gSofdecBufferPlacementMode = 0;
  std::uint32_t gSofdecPortBufferBytesPerChannel = 0x10000u;
  std::int32_t gSofdecSoundPortVtable1Tag = 0;
  std::int32_t gSofdecSoundPortVtable2Tag = 0;
  moho::MwsfdLibWork gMwsfdLibWork{};

  struct SflibErrorInfo
  {
    SflibErrorCallback callback = nullptr; // +0x00
    std::int32_t callbackObject = 0; // +0x04
    std::int32_t firstErrorCode = 0; // +0x08
    std::int32_t reserved0 = 0; // +0x0C
    std::int32_t reserved1 = 0; // +0x10
  };

  static_assert(offsetof(SflibErrorInfo, callback) == 0x00, "SflibErrorInfo::callback offset must be 0x00");
  static_assert(
    offsetof(SflibErrorInfo, callbackObject) == 0x04, "SflibErrorInfo::callbackObject offset must be 0x04"
  );
  static_assert(
    offsetof(SflibErrorInfo, firstErrorCode) == 0x08, "SflibErrorInfo::firstErrorCode offset must be 0x08"
  );
  static_assert(sizeof(SflibErrorInfo) == 0x14, "SflibErrorInfo size must be 0x14");

  struct SflibTransferInitRuntimeView
  {
    std::uint8_t mUnknown00[0x3C]{};
    std::int32_t resetParameter = 0; // +0x3C
    std::int32_t adxtHandle = 0; // +0x40
  };

  static_assert(
    offsetof(SflibTransferInitRuntimeView, resetParameter) == 0x3C,
    "SflibTransferInitRuntimeView::resetParameter offset must be 0x3C"
  );
  static_assert(
    offsetof(SflibTransferInitRuntimeView, adxtHandle) == 0x40,
    "SflibTransferInitRuntimeView::adxtHandle offset must be 0x40"
  );
  static_assert(sizeof(SflibTransferInitRuntimeView) == 0x44, "SflibTransferInitRuntimeView size must be 0x44");

  struct SflibLibWorkRuntime
  {
    std::array<std::uint32_t, 0x64> defaultConditions{}; // +0x000
    moho::MwsfdInitSfdParams initParams{}; // +0x190
    std::int32_t initState = 0; // +0x198
    SflibErrorInfo errInfo{}; // +0x19C
    std::uint8_t timeState[0x0C]{}; // +0x1B0
    std::uint8_t sfbufState[0x04]{}; // +0x1BC
    SflibTransferInitRuntimeView transferInitState{}; // +0x1C0
    std::array<void*, 32> objectHandles{}; // +0x204
    std::int32_t versionTag = 0; // +0x284
  };

  static_assert(
    offsetof(SflibLibWorkRuntime, defaultConditions) == 0x000,
    "SflibLibWorkRuntime::defaultConditions offset must be 0x000"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, initParams) == 0x190,
    "SflibLibWorkRuntime::initParams offset must be 0x190"
  );
  static_assert(offsetof(SflibLibWorkRuntime, initState) == 0x198, "SflibLibWorkRuntime::initState offset must be 0x198");
  static_assert(offsetof(SflibLibWorkRuntime, errInfo) == 0x19C, "SflibLibWorkRuntime::errInfo offset must be 0x19C");
  static_assert(
    offsetof(SflibLibWorkRuntime, timeState) == 0x1B0,
    "SflibLibWorkRuntime::timeState offset must be 0x1B0"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, sfbufState) == 0x1BC,
    "SflibLibWorkRuntime::sfbufState offset must be 0x1BC"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) == 0x1C0,
    "SflibLibWorkRuntime::transferInitState offset must be 0x1C0"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) + offsetof(SflibTransferInitRuntimeView, resetParameter) == 0x1FC,
    "SflibLibWorkRuntime::resetParameter offset must be 0x1FC"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, transferInitState) + offsetof(SflibTransferInitRuntimeView, adxtHandle) == 0x200,
    "SflibLibWorkRuntime::adxtHandle offset must be 0x200"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, objectHandles) == 0x204,
    "SflibLibWorkRuntime::objectHandles offset must be 0x204"
  );
  static_assert(
    offsetof(SflibLibWorkRuntime, versionTag) == 0x284,
    "SflibLibWorkRuntime::versionTag offset must be 0x284"
  );
  static_assert(sizeof(SflibLibWorkRuntime) == 0x288, "SflibLibWorkRuntime size must be 0x288");

  struct SflibErrorOwnerRuntimeView
  {
    std::uint8_t mUnknown00[0x48]{};
    std::int32_t handleState = 0; // +0x48
    std::uint8_t mUnknown4C[0x9AC]{};
    SflibErrorInfo errInfo{}; // +0x9F8
  };

  static_assert(
    offsetof(SflibErrorOwnerRuntimeView, handleState) == 0x48,
    "SflibErrorOwnerRuntimeView::handleState offset must be 0x48"
  );
  static_assert(
    offsetof(SflibErrorOwnerRuntimeView, errInfo) == 0x9F8,
    "SflibErrorOwnerRuntimeView::errInfo offset must be 0x9F8"
  );

  SflibLibWorkRuntime gSflibLibWork{};
  moho::MwsfdInitSfdParams gMwsfdInitSfdParams{};
  std::int32_t gMwsfdLastMwsfdHandle = 0;
  std::int32_t gMwsfdLastSfdHandle = 0;
  moho::MwsfdPlaybackStateSubobj* mwsfd_hn_last = nullptr;
  std::int32_t SFPLY_recordgetfrm = 0;
  moho::SofdecSfdWorkctrlSubobj* gSfdDebugLastHandle = nullptr;
  std::int32_t gMwsfdErrorCount = 0;
  std::int32_t gMwsfdErrorCodeHistory[16]{};
  char gMwsfdErrorString[0x100]{};
  const char* gMwsfdBackendErrorText = "";
  const char* gCriVerstrPtrCfg = "";
  const char* gCriVerstrPtrSfd = "";
  const char* gCriVerstrPtrCft = "";
  SfxaLibWorkView gSfxaLibWork{};
  const char* gCftcomFunctionName = nullptr;
  std::int32_t gCftcomOptimizeSpeed = 0;
  std::int32_t gUtySseSupportState = -1;
  std::int32_t gUtySse2SupportState = -1;
  std::int32_t gUtyMmxSupportState = -1;
  std::int32_t gUtyTimerInitCount = 0;
  std::int32_t gUtyTimerChannel = 0;
  std::int64_t gUtyTimerUnit = 0;
  std::int64_t sftim_as_pts = 0;
  std::int32_t sftim_a_sample = 0;
  std::int32_t sftim_v_time = 0;
  std::int32_t sftim_v_sample = 0;

  struct CriConfigEntry
  {
    std::array<char, 12> key{};
    std::int32_t value = 0;
  };
  static_assert(sizeof(CriConfigEntry) == 0x10, "CriConfigEntry size must be 0x10");

  CriConfigEntry* gCriConfigEntries = nullptr;
  std::int32_t gCriConfigEntryCount = 0;
  std::array<std::uint8_t, 0x100> gCriConfigEntryStorage{};

  struct CftYcc420PlanarInputLanes
  {
    std::uint8_t* yPlane = nullptr; // +0x00
    std::uint8_t* cbPlane = nullptr; // +0x04
    std::uint8_t* crPlane = nullptr; // +0x08
    std::int32_t yStrideBytes = 0; // +0x0C
    std::int32_t cbStrideBytes = 0; // +0x10
    std::int32_t crStrideBytes = 0; // +0x14
  };
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, yPlane) == 0x00,
    "CftYcc420PlanarInputLanes::yPlane offset must be 0x00"
  );
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, cbPlane) == 0x04,
    "CftYcc420PlanarInputLanes::cbPlane offset must be 0x04"
  );
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, crPlane) == 0x08,
    "CftYcc420PlanarInputLanes::crPlane offset must be 0x08"
  );
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, yStrideBytes) == 0x0C,
    "CftYcc420PlanarInputLanes::yStrideBytes offset must be 0x0C"
  );
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, cbStrideBytes) == 0x10,
    "CftYcc420PlanarInputLanes::cbStrideBytes offset must be 0x10"
  );
  static_assert(
    offsetof(CftYcc420PlanarInputLanes, crStrideBytes) == 0x14,
    "CftYcc420PlanarInputLanes::crStrideBytes offset must be 0x14"
  );
  static_assert(sizeof(CftYcc420PlanarInputLanes) == 0x18, "CftYcc420PlanarInputLanes size must be 0x18");

  struct CftPixelSurfaceLanes
  {
    std::uint8_t* pixelBase = nullptr; // +0x00
    std::int32_t widthPixels = 0; // +0x04
    std::int32_t heightPixels = 0; // +0x08
    std::int32_t strideBytes = 0; // +0x0C
    std::int32_t reserved = 0; // +0x10
  };
  static_assert(
    offsetof(CftPixelSurfaceLanes, pixelBase) == 0x00,
    "CftPixelSurfaceLanes::pixelBase offset must be 0x00"
  );
  static_assert(
    offsetof(CftPixelSurfaceLanes, widthPixels) == 0x04,
    "CftPixelSurfaceLanes::widthPixels offset must be 0x04"
  );
  static_assert(
    offsetof(CftPixelSurfaceLanes, heightPixels) == 0x08,
    "CftPixelSurfaceLanes::heightPixels offset must be 0x08"
  );
  static_assert(
    offsetof(CftPixelSurfaceLanes, strideBytes) == 0x0C,
    "CftPixelSurfaceLanes::strideBytes offset must be 0x0C"
  );
  static_assert(
    offsetof(CftPixelSurfaceLanes, reserved) == 0x10,
    "CftPixelSurfaceLanes::reserved offset must be 0x10"
  );
  static_assert(sizeof(CftPixelSurfaceLanes) == 0x14, "CftPixelSurfaceLanes size must be 0x14");

  std::array<std::int16_t, 0x10000> yuv_to_tmp{};
  std::array<std::uint32_t, 0x10000> yuv_to_r{};
  std::array<std::uint8_t, 0x10000> yuv_to_b{};
  std::array<std::uint16_t, 0x40000> tmp_to_g{};
  constexpr double kCftFixedPointScale = 65536.0;
  constexpr std::array<std::int32_t, 4> kCftDitherPatternWeights = {3, 1, 2, 4};
  std::array<std::int32_t, 0x100> y_to_y2_555{};
  std::array<std::int32_t, 0x100> cr_to_r_555{};
  std::array<std::int32_t, 0x100> cb_to_g_555{};
  std::array<std::int32_t, 0x100> cr_to_g_555{};
  std::array<std::int32_t, 0x100> cb_to_b_555{};
  std::array<std::int32_t, 0x300> r_to_pix_555{};
  std::array<std::int32_t, 0x300> g_to_pix_555{};
  std::array<std::int32_t, 0x300> b_to_pix_555{};
  std::array<std::int32_t, 0xC00> r_to_pix32_dither_555{};
  std::array<std::int32_t, 0xC00> g_to_pix32_dither_555{};
  std::array<std::int32_t, 0xC00> b_to_pix32_dither_555{};
  std::array<std::int32_t, 0x100> y_to_y2_565{};
  std::array<std::int32_t, 0x100> cr_to_r_565{};
  std::array<std::int32_t, 0x100> cb_to_g_565{};
  std::array<std::int32_t, 0x100> cr_to_g_565{};
  std::array<std::int32_t, 0x100> cb_to_b_565{};
  std::array<std::int32_t, 0x300> r_to_pix_565{};
  std::array<std::int32_t, 0x300> g_to_pix_565{};
  std::array<std::int32_t, 0x300> b_to_pix_565{};
  std::array<std::int32_t, 0xC00> r_to_pix32_dither_565{};
  std::array<std::int32_t, 0xC00> g_to_pix32_dither_565{};
  std::array<std::int32_t, 0xC00> b_to_pix32_dither_565{};
  constexpr char kDctBuildVersion[] = "\nCRI DCT/PC Ver.1.951 Build:Feb 28 2005 21:33:30\n";
  const char* gCriVersionStringDct = nullptr;
  const char* gDctAcVersionStringCache = nullptr;
  std::array<double, 64> gDctAcInverseTransformMatrix{};
  std::array<double, 64> gDctAcForwardTransformMatrix{};
  using M2vDispatchCallback = std::int32_t(__cdecl*)(...);
  using M2vVersionStringCallback = const char*(__cdecl*)();
  using M2vSimpleCallback = std::int32_t(__cdecl*)();
  using M2vDestroyCallback = std::int32_t(__cdecl*)(std::int32_t decoderHandle);
  using M2pVersionStringCallback = const char*(__cdecl*)();
  using M2pSimpleCallback = std::int32_t(__cdecl*)();
  std::int32_t m2vapi_issetup = 0;
  M2vVersionStringCallback m2vapi_GetVersionStr = nullptr;
  M2vSimpleCallback m2vapi_IsConformable = nullptr;
  M2vSimpleCallback m2vapi_Init = nullptr;
  M2vSimpleCallback m2vapi_Finish = nullptr;
  M2vSimpleCallback m2vapi_Create = nullptr;
  M2vDestroyCallback m2vapi_Destroy = nullptr;
  M2vSimpleCallback m2vapi_SetCond = nullptr;
  M2vDispatchCallback m2vapi_SetMbCb = nullptr;
  M2vDispatchCallback m2vapi_SetErrFunc = nullptr;
  M2vDispatchCallback m2vapi_GetErrInf = nullptr;
  M2vDispatchCallback m2vapi_DecodeFrm = nullptr;
  M2vDispatchCallback m2vapi_SkipFrm = nullptr;
  M2vDispatchCallback m2vapi_SetUsrSj = nullptr;
  M2vDispatchCallback m2vapi_SetPicUsrBuf = nullptr;
  M2vDispatchCallback m2vapi_GetPicUsr = nullptr;
  M2vDispatchCallback m2vapi_DecodePicAtr = nullptr;
  M2vDispatchCallback m2vapi_GetPicAtr = nullptr;
  M2vDispatchCallback m2vapi_GetBitRate = nullptr;
  M2vDispatchCallback m2vapi_GetVbvBufSiz = nullptr;
  M2vDispatchCallback m2vapi_GetLinkFlg = nullptr;
  std::int32_t m2sapi_m2p_issetup = 0;
  M2pVersionStringCallback m2sapi_m2p_GetVersionStr = nullptr;
  M2pSimpleCallback m2sapi_m2p_Init = nullptr;
  M2pSimpleCallback m2sapi_m2p_Finish = nullptr;
  M2pSimpleCallback m2sapi_m2p_IsConformable = nullptr;
  M2pSimpleCallback m2sapi_m2p_Create = nullptr;
  M2pSimpleCallback m2sapi_m2p_Destroy = nullptr;
  M2pSimpleCallback m2sapi_m2p_SetErrFn = nullptr;
  M2pSimpleCallback m2sapi_m2p_GetStat = nullptr;
  M2pSimpleCallback m2sapi_m2p_TermSupply = nullptr;
  M2pSimpleCallback m2sapi_m2p_DecHd = nullptr;
  M2pSimpleCallback m2sapi_m2p_SetAccessUnitTable = nullptr;
  M2pSimpleCallback m2sapi_m2p_SetPsMapFn = nullptr;
  M2pSimpleCallback m2sapi_m2p_SetPesFn = nullptr;

  using SofdecFrameReadCallback = std::uint32_t(__cdecl*)();
  SofdecFrameReadCallback gSofdecFrameReadCallback = nullptr;
  std::int32_t gSofdecSignalLane2 = 0;
  std::int32_t gAdxmInterval2 = 0;
  std::int32_t gSofdecScreenHeight2 = 0;
  std::int32_t gSofdecScanlineOffset = 0;
  std::int32_t gAdxmTimerSwitchState = 0;
  std::int32_t gAdxmTimerSwitchSignal = 0;
  MMRESULT gAdxmMultimediaTimerId = 0;
  LPTIMECALLBACK gAdxmMultimediaTimerCallback = nullptr;
  HANDLE gAdxmSyncEventHandle = nullptr;
  std::int64_t gAdxmPerformanceFrequency = 0;
  LARGE_INTEGER gAdxmLastSyncCounter{};
  LARGE_INTEGER gAdxmProbeCounter{};
  std::int32_t gAdxmInterval1 = 0;
  struct AdxmMwIdleSleepCallbackBinding
  {
    moho::AdxmMwIdleSleepCallback callback = nullptr;
    std::int32_t callbackParam = 0;
  };
  AdxmMwIdleSleepCallbackBinding gAdxmMwIdleSleepCallback{};
  std::int32_t gAdxmLockLevel = 0;
  CRITICAL_SECTION gAdxmLock{};
  std::int32_t gAdxmGotoMwIdleBorderFlag = 0;
  std::int32_t gAdxmVsyncCount = 0;
  std::int32_t gAdxmMwIdleCount = 0;
  std::int32_t gAdxmSpinWaitIterationCount = 0;
  std::int32_t gAdxmSpinWaitReleaseFlag = 0;
  std::int32_t gAdxmSpinWaitCompletedFlag = 0;
  std::int32_t gAdxmVsyncLoop = 0;
  std::int32_t gAdxmVsyncExit = 0;
  std::int32_t gAdxmFsLoop = 0;
  std::int32_t gAdxmFsExit = 0;
  std::int32_t gAdxmMwIdleLoop = 0;
  std::int32_t gAdxmMwIdleExit = 0;
  HANDLE gAdxmMwIdleThreadHandle = nullptr;
  HANDLE gAdxtVsyncEventHandle = nullptr;
  moho::AdxmThreadStartupParams gAdxmThreadStartupParams{};

  using SofdecTestAndSetOverride = BOOL(__cdecl*)(std::int32_t*);
  SofdecTestAndSetOverride gSofdecTestAndSetOverride = nullptr;

  using SvmLockCallback = void(__cdecl*)(std::int32_t callbackObject);
  using SvmErrorCallback = std::int32_t(__cdecl*)(std::uint32_t callbackObject, const char* message);

  struct SvmCallbackBinding
  {
    SvmLockCallback fn = nullptr;
    std::int32_t callbackObject = 0;
  };

  struct SvmErrorCallbackBinding
  {
    SvmErrorCallback fn = nullptr;
    std::int32_t callbackObject = 0;
  };

  SvmCallbackBinding gSvmLockCallback{};
  SvmCallbackBinding gSvmUnlockCallback{};
  SvmCallbackBinding gSvmPreWaitVCallback{};
  SvmCallbackBinding gSvmPostWaitVCallback{};
  std::array<SvmCallbackBinding, 8> gSvmServerBorderCallbacks{};
  SvmErrorCallbackBinding gSvmErrorCallback{};
  std::int32_t gSvmInitLevel = 0;
  std::int32_t gSvmLockLevel = 0;
  std::int32_t gSvmLockingType = 0;
  char gSvmErrorBuffer[0x80]{};
  char gSvmItoaScratchBuffer[0x80]{};
  using SvmServerCallbackFn = std::int32_t(__cdecl*)(std::int32_t callbackObject);
  struct SvmServerCallbackSlot
  {
    SvmServerCallbackFn callbackFn = nullptr;
    std::int32_t callbackObject = 0;
    const char* callbackName = nullptr;
  };
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackFn) == 0x00, "SvmServerCallbackSlot::callbackFn offset must be 0x00"
  );
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackObject) == 0x04,
    "SvmServerCallbackSlot::callbackObject offset must be 0x04"
  );
  static_assert(
    offsetof(SvmServerCallbackSlot, callbackName) == 0x08,
    "SvmServerCallbackSlot::callbackName offset must be 0x08"
  );
  static_assert(sizeof(SvmServerCallbackSlot) == 0x0C, "SvmServerCallbackSlot size must be 0x0C");
  std::array<SvmServerCallbackSlot, 48> gSvmServerCallbackTable{};
  std::array<std::int32_t, 8> gSvmServerExecutingFlags{};
  std::array<std::int32_t, 8> gSvmServerExecutionCounts{};
  std::int32_t gMwsfsvmVintSlotId = 0;
  std::int32_t gMwsfsvmVsyncSlotId = 0;
  std::int32_t gMwsfsvmIdleSlotId = 0;
  std::int32_t gMwsfsvmMainSlotId = 0;

  using AdxbExpandSamplePairCallback =
    void(__cdecl*)(moho::AdxBitstreamDecoderState* decoder, std::int32_t sampleValue, const std::int16_t* leftSample, const std::int16_t* rightSample);
  using AdxbUpdateSampleRateCallback =
    void(__cdecl*)(moho::AdxBitstreamDecoderState* decoder, std::int32_t sampleRate);

  void(__cdecl* ADXB_OnStopPostProcess)(moho::AdxBitstreamDecoderState* decoder) = nullptr;
  AdxbExpandSamplePairCallback ADXB_OnExpandSamplePair = nullptr;
  AdxbUpdateSampleRateCallback ADXB_OnUpdateSampleRate = nullptr;
}

namespace
{
  constexpr char kAdxCopyrightSignature[] = "(c)CRI";

  constexpr std::int32_t kSofdecSoundPortPoolSize = 32;
  constexpr DWORD kSofdecPrimaryBufferFlagsLegacy = 0x10080u;
  constexpr DWORD kSofdecPrimaryBufferFlagsDx8 = 0x10280u;
  constexpr DWORD kSofdecPrimaryBufferFlagsAlt = 0x100A0u;
  constexpr std::int32_t kSofdecLegacyDx8CapabilityTag = 0x800;
  constexpr std::int32_t kSofdecLegacyDx7CapabilityTag = 0x700;
  constexpr std::int32_t kSofdecPlaybackPollDivisor = 1500;
  constexpr char kSofdecErrChannelCountRange[] = "E1221:Illigal parameter(MAXNCH) in mwSndOpenPort().";
  constexpr char kSofdecErrNoFreeSoundPort[] = "E1222:Not enough instance(MWSND) in mwSndOpenPort().";
  constexpr char kSofdecErrCreateBuffer[] = "E1223:Cannot create DirectSoundBuffer in mwSndOpenPort().";
  constexpr char kSofdecErrNullPrimaryBuffer[] = "E1225:dsb(member in handle) is NULL";
  constexpr char kSofdecErrPlayFailed[] = "E1226:IDirectSoundBuffer_Play return error.";
  constexpr char kSofdecErrSetCurrentPositionFailed[] = "E1227:IDirectSoundBuffer_SetCurrentPosition return error.";
  constexpr char kSofdecErrSetFrequencyFailed[] = "E1228:IDirectSoundBuffer_SetFrequency return error.";
  constexpr char kSofdecErrCreatePlaybackFailed[] = "E1229:IDirectSoundBuffer_CreateSoundBuffer return error.";
  constexpr char kSofdecErrStopFailed[] = "E1229:IDirectSoundBuffer_Stop return error.";
  constexpr char kSofdecErrDirectSoundMissing[] = "E2003100700:DirectSound Object is NULL.";
  constexpr char kSofdecErrSetVolumeFailed[] = "E1230:IDirectSoundBuffer_SetVolume return error in mwSndSetVol";
  constexpr char kSofdecErrSetPanFailed[] = "E1232:IDirectSoundBuffer_SetPan return error in mwSndSetBalance";
  constexpr char kSofdecErrLockFailed[] = "E1234:IDirectSoundBuffer_Lock return error in mwSndGetData";
  constexpr char kSofdecErrUnlockFailed[] = "E1235:IDirectSoundBuffer_Unlock return error in mwSndGetData";
  constexpr char kSofdecErrControlSetFrequencyFailed[] = "E1236:IDirectSoundBuffer_SetFrequency return error in mwSndSetControl";
  constexpr char kCvFsDeviceMf[] = "MF";
  constexpr char kCvFsDeviceWx[] = "WX";
  constexpr char kCvFsVersionString[] = "\nCVFS/PC Ver.2.39 Build:Feb 28 2005 21:32:05\n";
  constexpr char kCvFsErrAddDevInvalidDeviceName[] = "cvFsAddDev #1:illegal device name";
  constexpr char kCvFsErrAddDevInvalidInterfaceFn[] = "cvFsAddDev #2:illegal I/F func name";
  constexpr char kCvFsErrAddDevFailed[] = "cvFsAddDev #3:failed added a device";
  constexpr char kCvFsErrDelDevInvalidDeviceName[] = "cvFsDelDev #1:illegal device name";
  constexpr char kCvFsErrSetDefDevInvalidDeviceName[] = "cvFsSetDefDev #1:illegal device name";
  constexpr char kCvFsErrSetDefDevUnknownDeviceName[] = "cvFsSetDefDev #2:unknown device name";
  constexpr char kCvFsErrCloseHandle[] = "cvFsClose #1:handle error";
  constexpr char kCvFsErrCloseVtable[] = "cvFsClose #2:vtbl error";
  constexpr char kCvFsErrOpenIllegalFileName[] = "cvFsOpen #1:illegal file name";
  constexpr char kCvFsErrOpenHandleAllocFailed[] = "cvFsOpen #3:failed handle alloced";
  constexpr char kCvFsErrOpenDeviceNotFound[] = "cvFsOpen #4:device not found";
  constexpr char kCvFsErrOpenVtableError[] = "cvFsOpen #5:vtbl error";
  constexpr char kCvFsErrOpenFailed[] = "cvFsOpen #6:open failed";
  constexpr char kCvFsErrSeekHandle[] = "cvFsSeek #1:handle error";
  constexpr char kCvFsErrSeekVtable[] = "cvFsSeek #2:vtbl error";
  constexpr char kCvFsErrGetStatHandle[] = "cvFsGetStat #1:handle error";
  constexpr char kCvFsErrGetStatVtable[] = "cvFsGetStat #2:vtbl error";
  constexpr char kCvFsErrGetDevNameVtable[] = "cvFsGetDevName #1:vtbl error";
  constexpr char kCvFsErrOptFn1Handle[] = "cvFsOptFn1 #1:handle error";
  constexpr char kCvFsErrOptFn1Vtable[] = "cvFsOptFn1 #2:vtbl error";
  constexpr char kCvFsErrOptFn2Handle[] = "cvFsOptFn2 #1:handle error";
  constexpr char kCvFsErrOptFn2Vtable[] = "cvFsOptFn2 #2:vtbl error";
  constexpr char kCvFsErrTellHandle[] = "cvFsTell #1:handle error";
  constexpr char kCvFsErrTellVtable[] = "cvFsTell #2:vtbl error";
  constexpr char kCvFsErrReqRdHandle[] = "cvFsReqRd #1:handle error";
  constexpr char kCvFsErrReqRdVtable[] = "cvFsReqRd #2:vtbl error";
  constexpr char kCvFsErrReqWrHandle[] = "cvFsReqWr #1:handle error";
  constexpr char kCvFsErrReqWrVtable[] = "cvFsReqWr #2:vtbl error";
  constexpr char kCvFsErrStopTrHandle[] = "cvFsStopTr #1:handle error";
  constexpr char kCvFsErrStopTrVtable[] = "cvFsStopTr #2:vtbl error";
  constexpr char kCvFsErrGetFileSizeIllegalFileName[] = "cvFsGetFileSize #1:illegal file name";
  constexpr char kCvFsErrGetFileSizeDeviceNotFound[] = "cvFsGetFileSize #3:device not found";
  constexpr char kCvFsErrGetFileSizeVtable[] = "cvFsGetFileSize #4:vtbl error";
  constexpr char kCvFsErrGetFileSizeExIllegalFileName[] = "cvFsGetFileSizeEx #1:illegal file name";
  constexpr char kCvFsErrGetFileSizeExDeviceNotFound[] = "cvFsGetFileSizeEx #3:device not found";
  constexpr char kCvFsErrGetFileSizeExVtable[] = "cvFsGetFileSizeEx #4:vtbl error";
  constexpr char kCvFsErrGetFileSizeByHandleIllegalHandle[] = "cvFsGetFileSizeByHndl #1:illegal file hndl";
  constexpr char kCvFsErrGetMaxByteRateHandle[] = "cvFsGetMaxByteRate #1:handle error";
  constexpr char kCvFsErrGetMaxByteRateVtable[] = "cvFsGetMaxByteRate #2:vtbl error";
  constexpr char kCvFsErrGetFreeSizeDeviceNotFound[] = "cvFsGetFreeSize #5:device not found";
  constexpr char kCvFsErrGetFreeSizeVtable[] = "cvFsGetFreeSize #6:vtbl error";
  constexpr char kCvFsErrGetSctLenHandle[] = "cvFsGetSctLen #1:handle error";
  constexpr char kCvFsErrGetSctLenVtable[] = "cvFsGetSctLen #2:vtbl error";
  constexpr char kCvFsErrSetSctLenHandle[] = "cvFsSetSctLen #3:handle error";
  constexpr char kCvFsErrSetSctLenVtable[] = "cvFsSetSctLen #4:vtbl error";
  constexpr char kCvFsErrGetNumTrHandle[] = "cvFsGetNumTr #1:handle error";
  constexpr char kCvFsErrGetNumTrVtable[] = "cvFsGetNumTr #2:vtbl error";
  constexpr char kCvFsErrChangeDirInvalidDirectory[] = "cvFsChangeDir #1:illegal directory name";
  constexpr char kCvFsErrChangeDirDeviceNotFound[] = "cvFsChangeDir #3:device not found";
  constexpr char kCvFsErrChangeDirVtable[] = "cvFsChangeDir #4:vtbl error";
  constexpr char kCvFsErrIsExistFileInvalidFileName[] = "cvFsIsExistFile #1:illegal file name";
  constexpr char kCvFsErrIsExistFileIllegalDeviceName[] = "cvFsIsExistFile #2:illegal device name";
  constexpr char kCvFsErrIsExistFileDeviceNotFound[] = "cvFsIsExistFile #3:device not found";
  constexpr char kCvFsErrIsExistFileVtable[] = "cvFsIsExistFile #4:vtbl error";
  constexpr char kCvFsErrMakeDirInvalidDirectory[] = "cvFsMakeDir #1:illegal directory name";
  constexpr char kCvFsErrMakeDirDeviceNotFound[] = "cvFsMakeDir #3:device not found";
  constexpr char kCvFsErrMakeDirVtable[] = "cvFsMakeDir #4:vtbl error";
  constexpr char kCvFsErrRemoveDirInvalidDirectory[] = "cvFsRemoveDir #1:illegal directory name";
  constexpr char kCvFsErrRemoveDirDeviceNotFound[] = "cvFsRemoveDir #3:device not found";
  constexpr char kCvFsErrRemoveDirVtable[] = "cvFsRemoveDir #4:vtbl error";
  constexpr char kCvFsErrDeleteFileInvalidFileName[] = "cvFsDeleteFile #1:illegal file name";
  constexpr char kCvFsErrDeleteFileDeviceNotFound[] = "cvFsDeleteFile #3:device not found";
  constexpr char kCvFsErrDeleteFileVtable[] = "cvFsDeleteFile #4:vtbl error";
  constexpr char kCvFsErrGetNumTr64Handle[] = "cvFsGetNumTr64 #1:handle error";
  constexpr char kCvFsErrGetFsys64InfoHandle[] = "cvFsGetFsys64Info #1:handle error";
  constexpr char kCvFsErrSetCurVolumeInvalidDeviceName[] = "cvFsSetCurVolume #1:illegal device name";
  constexpr char kCvFsErrSetCurVolumeInvalidVolumeName[] = "cvFsSetCurVolume #2:illegal image handle";
  constexpr char kCvFsErrSetCurVolumeDeviceNotFound[] = "cvFsSetCurVolume #3:device not found";
  constexpr char kCvFsErrAddVolumeExInvalidDeviceName[] = "cvFsAddVolumeEx #1:illegal device name";
  constexpr char kCvFsErrAddVolumeExInvalidVolumeName[] = "cvFsAddVolumeEx #2:illegal volume name";
  constexpr char kCvFsErrAddVolumeExInvalidImageHandle[] = "cvFsAddVolumeEx #3:illegal image handle";
  constexpr char kCvFsErrAddVolumeExDeviceNotFound[] = "cvFsAddVolumeEx #3:device not found";
  constexpr char kCvFsErrDelVolumeInvalidDeviceName[] = "cvFsDelVolume #1:illegal device name";
  constexpr char kCvFsErrDelVolumeInvalidVolumeName[] = "cvFsDelVolume #2:illegal volume name";
  constexpr char kCvFsErrDelVolumeDeviceNotFound[] = "cvFsDelVolume #3:device not found";
  constexpr char kCvFsErrGetVolumeInfoInvalidDeviceName[] = "cvFsGetVolumeInfo #1:illegal device name";
  constexpr char kCvFsErrGetVolumeInfoInvalidVolumeName[] = "cvFsGetVolumeInfo #2:illegal volume name";
  constexpr char kCvFsErrGetVolumeInfoDeviceNotFound[] = "cvFsGetVolumeInfo #3:device not found";
  constexpr char kCvFsErrSetDefVolInvalidDeviceName[] = "cvFsSetDefVol #1:illegal device name";
  constexpr char kCvFsErrSetDefVolInvalidVolumeName[] = "cvFsSetDefVol #2:illegal volume name";
  constexpr char kCvFsErrSetDefVolDeviceNotFound[] = "cvFsSetDefVol #3:device not found";
  constexpr std::int32_t kSvmServerTypeCount = 8;
  constexpr std::int32_t kSvmServerSlotsPerType = 6;
  constexpr std::int32_t kSvmUnlockTypeThread = 5;
  constexpr std::int32_t kSvmUnlockTypeEtc = 1000;
  constexpr std::int32_t kSvmItoaReverseDigitCap = 0x20;
  constexpr char kSvmUnknownServerCallbackName[] = "Unknown";
  constexpr char kSvmErrSetCbSvrTooManyServerFuncs[] = "1051001:SVM_SetCbSvr:too many server functions";
  constexpr char kSvmErrDelCbSvrIllegalId[] = "1051002:SVM_DelCbSvr:illegal id";
  constexpr char kSvmErrSetCbSvrIllegalSvType[] = "1071205:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrDelCbSvrIllegalSvType[] = "1071206:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrSetCbSvrIdIllegalId[] = "1071201:SVM_SetCbSvrId:illegal id";
  constexpr char kSvmErrSetCbSvrIdIllegalSvType[] = "1071202:SVM_SetCbSvrId:illegal svtype";
  constexpr char kSvmErrSetCbSvrIdOverwrite[] = "2100801:SVM_SetCbSvrId:over write callback function";
  constexpr char kSvmErrExecSvrFuncIdIllegalId[] = "1071301:SVM_ExecSvrFuncId:illegal id";
  constexpr char kSvmErrExecSvrFuncIdIllegalSvType[] = "1071302:SVM_ExecSvrFuncId:illegal svtype";
  constexpr char kSvmErrUnlockTypeMismatch[] = "2103102:SVM:svm_unlock:lock type miss match.(type org=%d, type now=%d)";
  constexpr char kAdxfSetReqRdSctStateReadingMessage[] = "E0041201:state is reading(ADXF_SetReqRdSct)";
  constexpr char kAdxfTellNullHandleMessage[] = "E9040827:'adxf' is NULL.(ADXF_Tell)";
  constexpr char kAdxfGetFsizeSctNullHandleMessage[] = "E9040828:'adxf' is NULL.(adxf_GetFsizeSct)";
  constexpr char kAdxfGetNumReqSctNullHandleMessage[] = "E9040830:'adxf' is NULL.(adxf_GetNumReqSct)";
  constexpr char kAdxfGetNumReadSctNullHandleMessage[] = "E9040831:'adxf' is NULL.(adxf_GetNumReadSct)";
  constexpr char kAdxfGetStatNullHandleMessage[] = "E9040832:'adxf' is NULL.(adxf_GetStat)";
  constexpr char kAdxfChkPrmGfrPtidOutOfRangeMessage[] = "E9040828:'ptid' is range outside.";
  constexpr char kAdxfChkPrmGfrFlidOutOfRangeMessage[] = "E9040828:'flid' is range outside.";
  constexpr char kAdxfChkPrmPtPartitionOutOfRangeMessage[] = "E9040801:partition ID is range outside.";
  constexpr char kAdxfChkPrmPtPointInfoNullMessage[] = "E9040802:'ptinfo' is NULL.(adxf_ChkPrmPt)";
  constexpr char kMwlRnaStartTransNullSjMessage[] = "E1212:mwlRnaStartTrans rna->sj=NULL";
  constexpr char kMwlRnaAddWrPosNullSjMessage[] = "E1213:mwlRnaAddWrPos rna->sj=NULL";
  constexpr std::int32_t kAdxrnaTransferDrainPollLimit = 200;
  constexpr char kMwRnaSetNumChanIllegalChannelMessage[] = "E1211:mwRnaSetNumChan Illegal parameter(NCH>MAXNCH)";
  constexpr char kMwRnaSetFxIllegalChannelMessage[] = "E1207:mwRnaSetFx Illegal parameter (FXCH)";
  constexpr char kAdxrnaIllegalParameterMessage[] = "E1205:Illegal parameter (MWRNA=NULL)";
  constexpr char kMwRnaCalcSfreqIllegalParameterMessage[] = "E1215:mwRnaCalcSfreq Illegal parameter(too big SFREQ)";
  constexpr char kUtyConfigTimerChannelKey[] = "TMR_CH";
  constexpr char kCriCfgVersionString[] = "\nCRI CFG/PC Ver.1.002 Build:Feb 28 2005 21:29:29\n";
  constexpr char kMwsfdRequiredVersion[] = "1.958";
  constexpr std::int32_t kMwsfdRequiredVersionTag = 0x3640;
  constexpr char kCriSfdVersionString[] = "\nCRI SFD/PC Ver.1.958 Build:Feb 28 2005 21:33:54\n";
  constexpr std::int32_t kMwsfdErrInitFailed = -301;
  constexpr std::int32_t kMwsfdErrSetErrFnFailed = -303;
  constexpr std::int32_t kMwsfdFileTypeMpv = 2;
  constexpr char kMwsfdErrIncompatibleVersion[] = "E011081 mwPlySfdInit: Not compatible SFD Version.";
  constexpr char kMwsfdErrStartFnameInvalidHandle[] = "E1122601: mwPlyStartFname: handle is invalid.";
  constexpr char kMwsfdErrStartFnameNullFileName[] = "E10915C: mwPlyStartFname: fname is NULL.";
  constexpr char kMwsfdErrInvalidHandle[] = "E1122630: mwPlyStartFnameLp: handle is invalid.";
  constexpr char kMwsfdErrNullFileName[] = "E10915A: mwPlyStartFnameLp: fname is NULL.";
  constexpr char kMwsfdErrConcatPlayFailed[] = "E99072103 mwPlyStartXX: can't link stream";
  constexpr char kMwsfdErrStopFailed[] = "E2003 mwSfdStop:can't stop SFD";
  constexpr char kMwsfdErrStartMemInvalidHandle[] = "E1122610 mwPlyStartMem: handle is invalid.";
  constexpr char kMwsfdErrStartMemUnsupportedMpv[] =
    "E4111701 mwPlyStartMem: can't play file type MPV. Use memory file system(MFS).";
  constexpr char kMwsfdErrStartSjInvalidHandle[] = "E1122609 mwPlyStartSj: handle is invalid.";
  constexpr char kMwsfdErrStartStreamReqStartFailedFmt[] = "E211141 MWSTM_ReqStart: can't start '%s'";
  constexpr char kMwsfdErrFileNameTooLong[] = "E211121: filename is longer.";
  constexpr char kMwsfdErrEntryFnameInvalidHandle[] = "E1122633: mwPlyEntryFname: handle is invalid.";
  constexpr char kMwsfdErrEntryFnameNullFileName[] = "E10915B: mwPlyEntryFname: fname is NULL.";
  constexpr char kMwsfdErrEntryFnameCannotEntryFmt[] = "E204021: mwPlyEntryFname: Can't entry file'%s'";
  constexpr char kMwsfdErrGetTimeInvalidHandle[] = "E1122603 mwPlyGetTime; handle is invalid.";
  constexpr char kMwsfdErrGetTimeFailed[] = "E2006 mwPlyGetTime; can't get time";
  constexpr char kMwsfdErrStartSeamlessInvalidHandle[] = "E1122634: mwPlyStartSeamless: handle is invalid.";
  constexpr char kMwsfdErrLinkStmInvalidHandle[] = "E1122642: mwPlyLinkStm: handle is invalid.";
  constexpr char kMwsfdErrLinkStmConcatPlayFailed[] = "E99072101 mwPlyLinkStm: can't link stream";
  constexpr char kMwsfdErrSetLpFlagInvalidHandle[] = "E1122641: mwPlySetLpFlg: handle is invalid.";
  constexpr char kMwsfdErrReleaseLpInvalidHandle[] = "E1122631: mwPlyReleaseLp: handle is invalid.";
  constexpr char kMwsfdErrReleaseSeamlessInvalidHandle[] = "E1122635: mwPlyReleaseSeamless: handle is invalid.";
  constexpr char kMwsfdErrStartAfsLpInvalidHandle[] = "E1122632: mwPlyStartAfsLp: handle is invalid.";
  constexpr char kMwsfdErrEntryAfsInvalidHandle[] = "E1122636: mwPlyEntryAfs: handle is invalid.";
  constexpr char kMwsfdErrEntryAfsCannotEntryFmt[] = "E008311 mwPlyEntryAfs: can't entry pid=%d fid=%d";
  constexpr char kMwsfdErrEntryFnameRangeInvalidHandle[] = "E407023: mwPlyEntryFnameRange: handle is invalid.";
  constexpr char kMwsfdErrStartFnameRangeLpInvalidHandle[] = "E407024: mwPlyStartFnameRangeLp: handle is invalid.";
  constexpr char kMwsfdErrGetCurFrmInvalidHandle[] = "E1122614: mwPlyGetCurFrm: handle is invalid.";
  constexpr char kMwsfdErrRelCurFrmInvalidHandle[] = "E1122615: mwPlyRelCurFrm: handle is invalid.";
  constexpr char kMwsfdErrStopInvalidHandle[] = "E1122602 mwSfdStop: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipDispInvalidHandle[] = "E202231: mwPlyGetNumSkipDisp: handle is invalid.";
  constexpr char kMwsfdErrGetSfdHandleInvalidHandle[] = "E1122640: mwPlyGetSfdHn: handle is invalid.";
  constexpr char kMwsfdErrGetNumDropFrmInvalidHandle[] = "E202232: mwPlyGetNumDropFrm: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipDecInvalidHandle[] = "E1122619: mwPlyGetNumSkipDec: handle is invalid.";
  constexpr char kMwsfdErrGetNumSkipEmptyBInvalidHandle[] = "E1122623: mwPlyGetNumSkipEmptyB: handle is invalid.";
  constexpr char kMwsfdErrGetPlyInfInvalidHandle[] = "E202191: mwPlyGetPlyInf: handle is invalid.";
  constexpr char kMwsfdErrForgotFree[] = "E2053005: forgot free.";
  constexpr char kMwsfdErrInvalidStreamIndexFmt[] = "E10821B : Invalid value of stm_no : %d";
  constexpr char kMwsfdErrGetSlFnameInvalidHandle[] = "E1122637: mwPlyGetSlFname: handle is invalid.";
  constexpr char kMwsfdErrGetCompoModeInvalidHandle[] = "E2011915: mwPlyFxGetCompoMode: handle is invalid.";
  constexpr char kMwsfdErrGetStatInvalidHandle[] = "W2004 mwPlyGetStat: handle is invalid";
  constexpr char kMwsfdErrExecSvrNullHandle[] = "E1071901 mwPlyExecSvrHndl: NULL handle.";
  constexpr char kMwsfdErrExecSvrPlayingTermFailed[] = "E99072102 mwlSfdExecDecSvrPlaying: can't term";
  constexpr char kMwsfdErrGetSyncModeInvalidHandle[] = "E2010802: mwPlyGetSyncMode: handle is invalid.";
  constexpr char kMwsfdErrGetSyncModeInvalidMode[] = "E2010803: mwPlyGetSyncMode: mode is invalid.";
  constexpr char kMwsfdErrSetOutBufSizeInvalidHandle[] = "E306091 MWSFSFX_SetOutBufSize: invalid handle";
  constexpr char kMwsfdErrMakeTblZ16InvalidHandle[] = "E202283: MWSFD_MakeTblZ16: handle is invalid.";
  constexpr char kMwsfdErrMakeTblZ16GetFrmFailed[] = "E202284: MWSFD_MakeTblZ16: getfrm is failed.";
  constexpr char kMwsfdErrMakeTblZ32InvalidHandle[] = "E202285: MWSFD_MakeTblZ32: handle is invalid.";
  constexpr char kMwsfdErrMakeTblZ32GetFrmFailed[] = "E202286: MWSFD_MakeTblZ32: getfrm is failed.";
  constexpr char kMwsfdErrMallocCountOver[] = "E2053001 MWSFD_Malloc: cnt over.";
  constexpr std::int32_t kMwsfdErrCodeInvalidHandle = -12;
  constexpr char kMwsfcreErrAttachPicUsrBufInternal[] = "E02120501: Internal Error: mwsfcre_AttachPicUsrBuf().";
  constexpr char kMwsfcreErrAttachPicUsrBufShort[] = "E02120502: mwsfcre_AttachPicUsrBuf(): usrdatbuf is short.";
  constexpr char kAdxfErrCreateNoHandles[] = "E04041201:not enough ADXF handle (adxf_CreateAdxFs)";
  constexpr char kAdxfErrCreateCannotCreateStream[] = "E02111001:can't create stm handle (adxf_CreateAdxFs)";
  constexpr std::int32_t kSflibErrInvalidHandleSetErrFn = static_cast<std::int32_t>(0xFF000101u);
  constexpr std::int32_t kSflibErrInvalidHandleGetErrInf = static_cast<std::int32_t>(0xFF000102u);
  constexpr std::int32_t kSflibErrDefaultConditionMissing = static_cast<std::int32_t>(0xFF000201u);
  constexpr std::int32_t kSflibErrCreateMissingWorkArea = static_cast<std::int32_t>(0xFF000204u);
  constexpr std::int32_t kSflibErrCreateWorkSizeTooSmall = static_cast<std::int32_t>(0xFF000205u);
  constexpr std::int32_t kSflibErrCreateNoFreeHandle = static_cast<std::int32_t>(0xFF000206u);
  constexpr std::int32_t kSflibErrInvalidHandleDestroy = static_cast<std::int32_t>(0xFF000131u);
  constexpr std::int32_t kSflibErrInvalidHandleStart = static_cast<std::int32_t>(0xFF000132u);
  constexpr std::int32_t kSflibErrInvalidHandleStop = static_cast<std::int32_t>(0xFF000133u);
  constexpr std::int32_t kSflibErrInvalidHandleGetCond = static_cast<std::int32_t>(0xFF000113u);
  constexpr std::int32_t kSflibErrInvalidHandleExecOne = static_cast<std::int32_t>(0xFF000138u);
  constexpr std::int32_t kSflibErrInvalidHandleTermSupply = static_cast<std::int32_t>(0xFF000135u);
  constexpr std::int32_t kAdxstmStatusFilesystemError = 4;
  constexpr char kCriCftVersionString[] = "\nCRI CFT/PC Ver.1.72 Build:Feb 28 2005 21:33:29\n";
  constexpr std::array<std::uint32_t, 0x64> kSfplyDefaultConditions = {
    0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000001u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0x00000001u, 0x00000000u, 0x00000001u,
    0x00000000u, 0x00000001u, 0xFFFFFFFDu, 0x00000001u, 0xFFFFFFFCu, 0x00000001u, 0x00000000u, 0x00000003u,
    0x00001000u, 0x00000000u, 0x00000001u, 0x0000003Cu, 0x00000001u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u, 0x00000000u,
    0xFFFF8AD0u, 0xFFFFC950u, 0x00001F40u, 0x0000EA24u, 0x00000FA0u, 0x00000FA0u, 0x00000029u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000005u, 0x00000000u, 0x00000005u, 0x022291E0u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x7FFFFFFFu, 0x00000000u, 0x00000000u, 0x00000001u, 0x0000000Au, 0x0000412Bu,
    0x00030D40u, 0x00000000u, 0x00000000u, 0x00000001u, 0x000104ACu, 0x00020958u, 0x0007D000u, 0x00000001u,
    0x00000001u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000001u,
    0x00000001u, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u, 0x00000000u,
    0x00000000u, 0x5A5A5A5Au, 0x00000000u, 0x00000000u,
  };
  constexpr char kSfxTagCompo[] = "COMPO";
  constexpr char kSfxErrUnsupportedCompo[] = "E4111902: sfxcnv_ChkCompoByCbFunc : compo is not support.";
  constexpr std::int32_t kSfxCompoModeHalfAlpha = 17;
  constexpr std::int32_t kSfxCompoModeFullAlpha = 33;
  constexpr std::int32_t kSfxCompoModeLookup = 49;
  constexpr std::int32_t kSfxCompoModeDynamicA = 65;
  constexpr std::int32_t kSfxCompoModeDynamicB = 81;
  constexpr std::int32_t kSfxCompoModeDynamicC = 97;
  constexpr std::int32_t kSfxCompoModeDirect = 257;
  constexpr std::int32_t kSfxCompoModeForcedLookup = 4097;
  constexpr std::int32_t kSfxCompoTableFullAlpha = 1;
  constexpr std::int32_t kSfxCompoTableLookup = 2;
  constexpr std::int32_t kSfxCompoTableForced = 21;
  constexpr std::int32_t kMwsfdErrorHistoryMaxIndex = 15;
  constexpr std::int32_t kMwsfdErrFramePoolSize = -16773355;
  constexpr std::int32_t kMwsfdErrRelFrameDoubleRelease = -16773345;
  constexpr std::int32_t kMwsfdErrMaxWidthHeightSmallMin = -16773353;
  constexpr std::int32_t kMwsfdErrMaxWidthHeightSmallMax = -16773352;
  constexpr std::int32_t kMwsfdErrReadBufferSmallA = -16773348;
  constexpr std::int32_t kMwsfdErrLibraryMessage = -16776143;
  constexpr std::int32_t kMwsfdErrReadBufferSmallB = -16776184;
  constexpr std::int32_t kMwsfdErrReadBufferSmallC = -16776180;
  constexpr std::int32_t kMwsfdErrAdxtHandleLimit = -16774140;
  constexpr std::int32_t kMwsfdErrDataLowerBound = -3;
  constexpr std::int32_t kMwsfdErrDataUpperBound = -2;
  constexpr char kMwsfdFmtSfdError[] = "SFD ERROR(%08X)";
  constexpr char kMwsfdFmtSfdErrorWithText[] = "SFD ERROR(%08X): %s";
  constexpr char kMwsfdFmtDataError[] = "DATA ERROR(%08X)";
  constexpr char kMwsfdMsgFramePoolSize[] =
    "SFD ERROR(%08X): Frame pool size is incorrect. Set positive integer to 'nfrm_pool_wk' of creation parameter.";
  constexpr char kMwsfdMsgRelFrameDoubleRelease[] =
    "SFD ERROR(%08X): mwPlyRelFrm() was called twice to the same frame ID.";
  constexpr char kMwsfdMsgMaxWidthHeightSmall[] =
    "SFD ERROR(%08X): 'max_width, max_height' of creation parameter is small. Increase this value.";
  constexpr char kMwsfdMsgReadBufferSmall[] =
    "SFD ERROR(%08X): Read buffer is small. Increase 'max_bps' of creation parameter.";
  constexpr char kMwsfdMsgAdxtHandleLimit[] =
    "SFD ERROR(%08X): Number of ADXT handles exceeds its maximum number. MWPLY handle uses one ADXT handle(stereo) for MWSFD_FTYPE_SFD.";
  constexpr std::int32_t kSofdecMinMillibel = -10000;
  constexpr std::int32_t kSofdecMaxMillibel = 0;
  constexpr std::int32_t kSofdecBalanceIndexMin = -15;
  constexpr std::int32_t kSofdecBalanceIndexMax = 15;
  constexpr std::int32_t kSofdecFrequencyMinHz = 100;
  constexpr std::int32_t kSofdecFrequencyMaxHz = 100000;

  constexpr std::array<std::int32_t, 31> kSofdecBalancePanTable = {
    -10000,
    -7356,
    -5411,
    -3981,
    -2928,
    -2154,
    -1584,
    -1165,
    -857,
    -630,
    -464,
    -341,
    -251,
    -184,
    -135,
    0,
    135,
    184,
    251,
    341,
    464,
    630,
    857,
    1165,
    1584,
    2154,
    2928,
    3981,
    5411,
    7356,
    10000,
  };

  constexpr std::array<std::int32_t, 31> kSofdecSpatialPanTable = {
    -10000,
    -2561,
    -1957,
    -1600,
    -1345,
    -1144,
    -976,
    -831,
    -702,
    -586,
    -477,
    -375,
    -278,
    -183,
    -91,
    0,
    91,
    183,
    278,
    375,
    477,
    586,
    702,
    831,
    976,
    1144,
    1345,
    1600,
    1957,
    2561,
    10000,
  };

  constexpr std::array<std::int32_t, 31> kSofdecSpatialVolumeOffsetTable = {
    0,
    -1,
    -5,
    -11,
    -19,
    -30,
    -44,
    -60,
    -79,
    -100,
    -125,
    -153,
    -184,
    -219,
    -258,
    -301,
    -258,
    -219,
    -184,
    -153,
    -125,
    -100,
    -79,
    -60,
    -44,
    -30,
    -19,
    -11,
    -5,
    -1,
    0,
  };

  constexpr std::array<float, 31> kSofdecPanGainTable = {
    1.0f,
    0.9986295104f,
    0.9945219159f,
    0.9876883626f,
    0.9781476259f,
    0.9659258127f,
    0.9510565400f,
    0.9335803986f,
    0.9135454297f,
    0.8910065293f,
    0.8660253882f,
    0.8386705518f,
    0.8090170026f,
    0.7771459818f,
    0.7431448102f,
    0.7071067691f,
    0.6691306233f,
    0.6293203831f,
    0.5877852440f,
    0.5446390510f,
    0.5f,
    0.4539904892f,
    0.4067366421f,
    0.3583679497f,
    0.3090170026f,
    0.2588190436f,
    0.2079116851f,
    0.1564344615f,
    0.1045284644f,
    0.0523359552f,
    0.0f,
  };

  [[nodiscard]] std::uint32_t SofdecComputeStereoSamplePairCount(const std::int32_t byteCount)
  {
    std::int32_t adjusted = byteCount;
    adjusted -= (adjusted >> 31);
    adjusted >>= 1;
    return static_cast<std::uint32_t>(adjusted) >> 1u;
  }

  [[nodiscard]] float SofdecLookupPanGainByIndex(const std::int32_t index)
  {
    return kSofdecPanGainTable[static_cast<std::size_t>(index)];
  }

  [[nodiscard]] float SofdecLookupLeftPanGain(const std::int32_t panLane)
  {
    std::int32_t lookupIndex = panLane + 15;
    if (lookupIndex < 0) {
      lookupIndex = -15 - panLane;
    }
    return SofdecLookupPanGainByIndex(lookupIndex);
  }

  [[nodiscard]] float SofdecLookupRightPanGain(const std::int32_t panLane)
  {
    std::int32_t lookupIndex = panLane - 15;
    if (lookupIndex < 0) {
      lookupIndex = 15 - panLane;
    }
    return SofdecLookupPanGainByIndex(lookupIndex);
  }

  [[nodiscard]] std::int32_t SofdecRoundFloatToInt(const float value)
  {
    return static_cast<std::int32_t>(std::lrintf(value));
  }

  [[nodiscard]] std::int16_t SofdecClampSampleToPcm16(const std::int32_t sampleValue)
  {
    if (sampleValue > 0x7FFF) {
      return static_cast<std::int16_t>(0x7FFF);
    }
    if (sampleValue < -32768) {
      return static_cast<std::int16_t>(-32768);
    }
    return static_cast<std::int16_t>(sampleValue);
  }

  [[nodiscard]] std::int32_t SofdecClampMillibel(const std::int32_t value)
  {
    if (value > kSofdecMaxMillibel) {
      return kSofdecMaxMillibel;
    }
    if (value < kSofdecMinMillibel) {
      return kSofdecMinMillibel;
    }
    return value;
  }

  [[nodiscard]] std::int32_t SofdecLookupBalancePanMillibel(const std::int32_t balanceIndex)
  {
    return kSofdecBalancePanTable[static_cast<std::size_t>(balanceIndex - kSofdecBalanceIndexMin)];
  }

  [[nodiscard]] std::int32_t SofdecLookupSpatialPanMillibel(const std::int32_t spatialIndex)
  {
    return kSofdecSpatialPanTable[static_cast<std::size_t>(spatialIndex - kSofdecBalanceIndexMin)];
  }

  [[nodiscard]] std::int32_t SofdecLookupSpatialVolumeOffsetMillibel(const std::int32_t spatialIndex)
  {
    return kSofdecSpatialVolumeOffsetTable[static_cast<std::size_t>(spatialIndex - kSofdecBalanceIndexMin)];
  }

  void SofdecPollBufferPlaybackState(IDirectSoundBuffer* const soundBuffer, const bool waitForPlayingState)
  {
    LARGE_INTEGER startCounter{};
    QueryPerformanceCounter(&startCounter);

    DWORD status = 0;
    soundBuffer->lpVtbl->GetStatus(soundBuffer, &status);

    while (((status & DSBSTATUS_PLAYING) != 0) != waitForPlayingState) {
      LARGE_INTEGER frequency{};
      QueryPerformanceFrequency(&frequency);
      frequency.QuadPart /= kSofdecPlaybackPollDivisor;

      LARGE_INTEGER currentCounter{};
      QueryPerformanceCounter(&currentCounter);

      if ((currentCounter.QuadPart - startCounter.QuadPart) > frequency.QuadPart) {
        break;
      }
      if (currentCounter.QuadPart <= startCounter.QuadPart) {
        break;
      }

      soundBuffer->lpVtbl->GetStatus(soundBuffer, &status);
    }
  }

  constexpr std::int32_t kM2aMaxBandsLong = 49;
  constexpr std::int32_t kM2aMaxBandsShort = 14;
  constexpr std::int32_t kM2aShortWindowCount = 8;
  constexpr std::int32_t kM2aTnsCoefficientLaneCount = 32;
  constexpr std::int32_t kM2aIcsMaxSfbIndex = 140;
  constexpr std::int32_t kM2aIcsWindowSequenceIndex = 122;
  constexpr std::int32_t kM2aIcsWindowShapeIndex = 123;
  constexpr std::int32_t kM2aIcsIntensityScaleBaseIndex = 114;
  constexpr std::int32_t kM2aContextStatusIndex = 1;
  constexpr std::int32_t kM2aContextErrorCodeIndex = 2;
  constexpr std::int32_t kM2aContextHeapManagerIndex = 5;
  constexpr std::int32_t kM2aContextAudioObjectTypeIndex = 19;
  constexpr std::int32_t kM2aContextSampleRateIndex = 20;
  constexpr std::int32_t kM2aContextSampleRateTableIndex = 21;
  constexpr std::int32_t kM2aContextDecodedChannelCountIndex = 23;
  constexpr std::int32_t kM2aContextDecodeCountInitializedIndex = 33;
  constexpr std::int32_t kM2aContextScalefactorBandLongPtrIndex = 35;
  constexpr std::int32_t kM2aContextScalefactorBandShortPtrIndex = 36;
  constexpr std::int32_t kM2aContextPceMapIndex = 38;
  constexpr std::int32_t kM2aContextLocationEntryBaseIndex = 39;
  constexpr std::int32_t kM2aContextLocationAllocBaseIndex = 156;
  constexpr std::int32_t kM2aContextIcsTableBaseIndex = 167;
  constexpr std::int32_t kM2aContextSecondaryIcsTableBaseIndex = 183;
  constexpr std::int32_t kM2aContextPrimaryStateBaseIndex = 423;
  constexpr std::int32_t kM2aContextSecondaryStateBaseIndex = 439;
  constexpr std::int32_t kM2aContextElementIndex = 10;
  constexpr std::int32_t kM2aContextWindowGroupIndex = 11;
  constexpr std::int32_t kM2aContextLocationEntryCountIndex = 88;
  constexpr double kM2aIntensityPowBase = 0.5;
  constexpr double kM2aIntensityPowScale = 0.25;
  constexpr std::size_t kM2aLocationEntrySize = 0x0Cu;
  constexpr std::size_t kM2aIcsInfoSize = 0x234u;
  constexpr std::size_t kM2aDecodeStateSize = 0x88ECu;
  constexpr std::size_t kM2aDecoderContextSize = 0xA9Cu;
  constexpr std::size_t kM2aScratchMappingBytes = 0x34u;
  constexpr std::size_t kM2aPceMapBytes = 0x2B8u;
  constexpr std::int32_t kM2aLocationEntryCapacity = 128;
  constexpr std::int32_t kM2aDecoderSlotCount = 256;
  constexpr std::int32_t kM2aContextScratchMappingIndex = 37;
  constexpr std::int32_t kM2aContextInputBufferIndex = 6;
  constexpr std::int32_t kM2aContextInputByteCountIndex = 7;
  constexpr std::int32_t kM2aContextInputBitRemainderIndex = 8;
  constexpr std::int32_t kM2aContextElementCounterIndex = 12;
  constexpr std::int32_t kM2aContextElementCounterLimitIndex = 13;
  constexpr std::int32_t kM2aContextFrameCounterIndex = 14;
  constexpr std::int32_t kM2aContextPendingSupplyIndex = 15;
  constexpr std::int32_t kM2aContextEndModeIndex = 16;
  constexpr std::int32_t kM2aContextHeaderTypeIndex = 17;
  constexpr std::int32_t kM2aContextBitstreamHandleIndex = 9;
  constexpr std::int32_t kM2aContextAdtsFrameLengthIndex = 12;
  constexpr std::int32_t kM2aContextAdtsRawBlockCountIndex = 13;
  constexpr std::int32_t kM2aContextChannelConfigurationIndex = 24;
  constexpr std::int32_t kM2aContextLayoutInitializedIndex = 34;
  constexpr std::int32_t kM2aPceMixdownTableIndex = 171;
  constexpr std::int32_t kM2aPceSurroundMixdownEnabledIndex = 172;
  constexpr std::int32_t kM2aElementIdEnd = 7;
  constexpr std::int32_t kM2aMainProfile = 1;
  constexpr std::int32_t kM2aDecodeStateOutputReadySamplesIndex = 8762;
  constexpr std::ptrdiff_t kM2aDecodeStatePcmWindowOffset = 0x78E4;
  constexpr std::int32_t kM2aPcmWindowSampleCount = 1024;
  constexpr float kM2aCenterDownmixScale = 0.70710677f;
  constexpr float kM2aMonoDownmixScale = 0.5f;
  constexpr std::uint32_t kM2aDownmixBufferBytes =
    static_cast<std::uint32_t>(kM2aPcmWindowSampleCount * sizeof(float));

  struct AdxbRuntimeView
  {
    std::int16_t slotState = 0; // +0x00
    std::int16_t initState = 0; // +0x02
    std::int32_t runState = 0; // +0x04
    void* adxPacketDecoder = nullptr; // +0x08
    std::int8_t headerType = 0; // +0x0C
    std::int8_t sourceSampleBits = 0; // +0x0D
    std::int8_t sourceChannels = 0; // +0x0E
    std::int8_t sourceBlockBytes = 0; // +0x0F
    std::int32_t sourceBlockSamples = 0; // +0x10
    std::int32_t sampleRate = 0; // +0x14
    std::int32_t totalSampleCount = 0; // +0x18
    std::int16_t adpcmCoefficientIndex = 0; // +0x1C
    std::uint8_t mUnknown1E[0x2]{}; // +0x1E
    std::int32_t loopInsertedSamples = 0; // +0x20
    std::int16_t loopCount = 0; // +0x24
    std::uint16_t loopType = 0; // +0x26
    std::int32_t loopStartSample = 0; // +0x28
    std::int32_t loopStartOffset = 0; // +0x2C
    std::int32_t loopEndSample = 0; // +0x30
    std::int32_t loopEndOffset = 0; // +0x34
    void* pcmBufferTag = nullptr; // +0x38
    std::int16_t* pcmBuffer0 = nullptr; // +0x3C
    std::int32_t pcmBufferSampleLimit = 0; // +0x40
    std::int32_t pcmBufferSecondChannelOffset = 0; // +0x44
    char* sourceWordStream = nullptr; // +0x48
    std::int32_t sourceWordLimit = 0; // +0x4C
    std::int32_t outputChannels = 0; // +0x50
    std::int32_t outputBlockBytes = 0; // +0x54
    std::int32_t outputBlockSamples = 0; // +0x58
    std::int16_t* outputWordStream0 = nullptr; // +0x5C
    std::int32_t outputWordLimit = 0; // +0x60
    std::int32_t outputSecondChannelOffset = 0; // +0x64
    std::int32_t entryWriteStartWordIndex = 0; // +0x68
    std::int32_t entryWriteUsedWordCount = 0; // +0x6C
    std::int32_t entryWriteCapacityWords = 0; // +0x70
    std::int32_t callbackLane3 = 0; // +0x74
    void(__cdecl* entryGetWriteFunc)(std::int32_t, std::int32_t*, std::int32_t*, std::int32_t*) = nullptr; // +0x78
    std::int32_t entryGetWriteContext = 0; // +0x7C
    std::int32_t(__cdecl* entryAddWriteFunc)(std::int32_t, std::int32_t, std::int32_t) = nullptr; // +0x80
    std::int32_t entryAddWriteContext = 0; // +0x84
    std::int32_t entrySubmittedBytes = 0; // +0x88
    std::int32_t entryCommittedBytes = 0; // +0x8C
    std::int32_t producedSampleCount = 0; // +0x90
    std::int32_t producedByteCount = 0; // +0x94
    std::int16_t format = 0; // +0x98
    std::int16_t preferredFormat = 0; // +0x9A
    std::int16_t outputSamplePacking = 0; // +0x9C
    std::uint8_t mUnknown9E[0x2]{}; // +0x9E
    std::uint8_t mUnknownA0[0x14]{}; // +0xA0
    void* ahxDecoderHandle = nullptr; // +0xB4
    std::int32_t ahxMaxDecodeSamples = 0; // +0xB8
    std::int32_t ahxMaxDecodeBlocks = 0; // +0xBC
    std::uint8_t mUnknownC0[0x4]{}; // +0xC0
    std::int32_t mpaDecodeSampleLimit = 0; // +0xC4
    std::int32_t mpaDecodeBlockLimit = 0; // +0xC8
    std::uint8_t mUnknownCC[0x28]{}; // +0xCC
    std::int32_t channelExpandHandle = 0; // +0xF4
    std::int32_t expandMatrixParamA = 0; // +0xF8
    std::int32_t expandMatrixParamB = 0; // +0xFC
    std::int32_t decodeCallbackConsumedBytes = 0; // +0x100
    std::uint8_t mUnknown104[0x4]{}; // +0x104
    std::int32_t(__cdecl* decodeCallback)(std::int32_t callbackContext, std::int32_t producedDelta, std::int32_t producedBytes) = nullptr; // +0x108
    std::int32_t decodeCallbackContext = 0; // +0x10C
  };

  static_assert(offsetof(AdxbRuntimeView, runState) == 0x04, "AdxbRuntimeView::runState offset must be 0x04");
  static_assert(offsetof(AdxbRuntimeView, adxPacketDecoder) == 0x08, "AdxbRuntimeView::adxPacketDecoder offset must be 0x08");
  static_assert(offsetof(AdxbRuntimeView, sourceChannels) == 0x0E, "AdxbRuntimeView::sourceChannels offset must be 0x0E");
  static_assert(offsetof(AdxbRuntimeView, sourceWordStream) == 0x48, "AdxbRuntimeView::sourceWordStream offset must be 0x48");
  static_assert(offsetof(AdxbRuntimeView, outputChannels) == 0x50, "AdxbRuntimeView::outputChannels offset must be 0x50");
  static_assert(offsetof(AdxbRuntimeView, outputWordStream0) == 0x5C, "AdxbRuntimeView::outputWordStream0 offset must be 0x5C");
  static_assert(
    offsetof(AdxbRuntimeView, entryGetWriteFunc) == 0x78, "AdxbRuntimeView::entryGetWriteFunc offset must be 0x78"
  );
  static_assert(
    offsetof(AdxbRuntimeView, entryAddWriteFunc) == 0x80, "AdxbRuntimeView::entryAddWriteFunc offset must be 0x80"
  );
  static_assert(
    offsetof(AdxbRuntimeView, producedSampleCount) == 0x90, "AdxbRuntimeView::producedSampleCount offset must be 0x90"
  );
  static_assert(
    offsetof(AdxbRuntimeView, producedByteCount) == 0x94, "AdxbRuntimeView::producedByteCount offset must be 0x94"
  );
  static_assert(
    offsetof(AdxbRuntimeView, channelExpandHandle) == 0xF4,
    "AdxbRuntimeView::channelExpandHandle offset must be 0xF4"
  );
  static_assert(
    offsetof(AdxbRuntimeView, expandMatrixParamA) == 0xF8,
    "AdxbRuntimeView::expandMatrixParamA offset must be 0xF8"
  );
  static_assert(
    offsetof(AdxbRuntimeView, expandMatrixParamB) == 0xFC,
    "AdxbRuntimeView::expandMatrixParamB offset must be 0xFC"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxDecoderHandle) == 0xB4,
    "AdxbRuntimeView::ahxDecoderHandle offset must be 0xB4"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxMaxDecodeSamples) == 0xB8,
    "AdxbRuntimeView::ahxMaxDecodeSamples offset must be 0xB8"
  );
  static_assert(
    offsetof(AdxbRuntimeView, ahxMaxDecodeBlocks) == 0xBC,
    "AdxbRuntimeView::ahxMaxDecodeBlocks offset must be 0xBC"
  );
  static_assert(
    offsetof(AdxbRuntimeView, mpaDecodeSampleLimit) == 0xC4,
    "AdxbRuntimeView::mpaDecodeSampleLimit offset must be 0xC4"
  );
  static_assert(
    offsetof(AdxbRuntimeView, mpaDecodeBlockLimit) == 0xC8,
    "AdxbRuntimeView::mpaDecodeBlockLimit offset must be 0xC8"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallbackConsumedBytes) == 0x100,
    "AdxbRuntimeView::decodeCallbackConsumedBytes offset must be 0x100"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallback) == 0x108, "AdxbRuntimeView::decodeCallback offset must be 0x108"
  );
  static_assert(
    offsetof(AdxbRuntimeView, decodeCallbackContext) == 0x10C,
    "AdxbRuntimeView::decodeCallbackContext offset must be 0x10C"
  );
  static_assert(sizeof(AdxbRuntimeView) == 0x110, "AdxbRuntimeView size must be 0x110");

  struct AdxPacketDecodeSampleView
  {
    std::uint8_t mUnknown00[0x10]{}; // +0x00
    std::int32_t sourceChannels = 0; // +0x10
    std::uint8_t mUnknown14[0x0C]{}; // +0x14
    std::uint8_t* primaryOutputBytes = nullptr; // +0x20
    std::uint8_t* secondaryOutputBytes = nullptr; // +0x24
  };

  static_assert(
    offsetof(AdxPacketDecodeSampleView, sourceChannels) == 0x10,
    "AdxPacketDecodeSampleView::sourceChannels offset must be 0x10"
  );
  static_assert(
    offsetof(AdxPacketDecodeSampleView, primaryOutputBytes) == 0x20,
    "AdxPacketDecodeSampleView::primaryOutputBytes offset must be 0x20"
  );
  static_assert(
    offsetof(AdxPacketDecodeSampleView, secondaryOutputBytes) == 0x24,
    "AdxPacketDecodeSampleView::secondaryOutputBytes offset must be 0x24"
  );

  struct AdxtDolbyRuntimeState
  {
    void* workBufferBase = nullptr; // +0x00
    std::int32_t workBufferBytes = 0; // +0x04
    std::int32_t* historyLaneA = nullptr; // +0x08
    std::int32_t* historyLaneB = nullptr; // +0x0C
    std::int32_t sampleRate = 0; // +0x10
    std::int32_t historyWriteIndex = 0; // +0x14
    std::int32_t historyWindowLength = 0; // +0x18
    std::int32_t mixTableIndexA = 0; // +0x1C
    std::int32_t mixTableIndexB = 0; // +0x20
    std::int32_t mixTableIndexC = 0; // +0x24
    std::int32_t mixTableIndexD = 0; // +0x28
  };

  static_assert(
    offsetof(AdxtDolbyRuntimeState, workBufferBase) == 0x00,
    "AdxtDolbyRuntimeState::workBufferBase offset must be 0x00"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, workBufferBytes) == 0x04,
    "AdxtDolbyRuntimeState::workBufferBytes offset must be 0x04"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyLaneA) == 0x08,
    "AdxtDolbyRuntimeState::historyLaneA offset must be 0x08"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyLaneB) == 0x0C,
    "AdxtDolbyRuntimeState::historyLaneB offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, sampleRate) == 0x10, "AdxtDolbyRuntimeState::sampleRate offset must be 0x10"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyWriteIndex) == 0x14,
    "AdxtDolbyRuntimeState::historyWriteIndex offset must be 0x14"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, historyWindowLength) == 0x18,
    "AdxtDolbyRuntimeState::historyWindowLength offset must be 0x18"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexA) == 0x1C,
    "AdxtDolbyRuntimeState::mixTableIndexA offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexB) == 0x20,
    "AdxtDolbyRuntimeState::mixTableIndexB offset must be 0x20"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexC) == 0x24,
    "AdxtDolbyRuntimeState::mixTableIndexC offset must be 0x24"
  );
  static_assert(
    offsetof(AdxtDolbyRuntimeState, mixTableIndexD) == 0x28,
    "AdxtDolbyRuntimeState::mixTableIndexD offset must be 0x28"
  );
  static_assert(sizeof(AdxtDolbyRuntimeState) == 0x2C, "AdxtDolbyRuntimeState size must be 0x2C");

  struct AdxtDestroyableHandle
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Destroy() = 0; // +0x14
  };

  struct AdxtStreamJoinHandle
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void OnSeamlessStart() = 0; // +0x14
    virtual void AcquireChunk(std::int32_t lane, std::int32_t requestedBytes, SjChunkRange* outChunkRange) = 0; // +0x18
    virtual void ReturnChunk(std::int32_t lane, const SjChunkRange* chunkRange) = 0; // +0x1C
    virtual void CommitChunk(std::int32_t lane, const SjChunkRange* chunkRange) = 0; // +0x20
    virtual std::int32_t QueryDecodeBacklog(std::int32_t lane) = 0; // +0x24
  };

  struct AdxsjdOutputHandle
  {
    virtual void Reserved00() = 0;
    virtual void Reserved04() = 0;
    virtual void Reserved08() = 0;
    virtual void Reserved0C() = 0;
    virtual void Reserved10() = 0;
    virtual void Reserved14() = 0;
    virtual void GetChunk(std::int32_t lane, std::int32_t requestedBytes, SjChunkRange* outChunkRange) = 0; // +0x18
  };

  struct AdxtDecodeSourceHandle : AdxtDestroyableHandle
  {
    virtual void Reserved18() = 0;
    virtual void Reserved1C() = 0;
    virtual void Reserved20() = 0;
    virtual std::int32_t QueryDecodeBacklog(std::int32_t lane) = 0; // +0x24
  };

  struct AdxtRuntimeState
  {
    std::uint8_t used = 0; // +0x00
    std::uint8_t mUnknown01 = 0; // +0x01
    std::uint8_t mUnknown02 = 0; // +0x02
    std::int8_t maxChannelCount = 0; // +0x03
    std::int32_t sjdHandle = 0; // +0x04
    void* streamHandle = nullptr; // +0x08
    std::int32_t rnaHandle = 0; // +0x0C
    AdxtDestroyableHandle* sourceRingHandle = nullptr; // +0x10
    AdxtStreamJoinHandle* streamJoinInputHandle = nullptr; // +0x14
    std::uint8_t mUnknown18[0x24]{}; // +0x18
    std::int16_t streamBufferSectorLimitHint = 0; // +0x3C
    std::int16_t seamlessFlowSectorHint = 0; // +0x3E
    std::uint8_t mUnknown40[0x0C]{}; // +0x40
    std::int32_t streamStartScratchWord = 0; // +0x4C
    std::uint8_t mUnknown50[0x21]{}; // +0x50
    std::uint8_t streamStartLatchByte = 0; // +0x71
    std::uint8_t mUnknown72[0x02]{}; // +0x72
    void* channelExpandHandle = nullptr; // +0x74
    std::uint8_t mUnknown78[0x10]{}; // +0x78
    std::int32_t linkReadCursor = 0; // +0x88
    std::int32_t streamEndSector = 0; // +0x8C
    std::int32_t streamLoopStartSample = 0; // +0x90
    void* linkControlHandle = nullptr; // +0x94
    std::uint8_t linkSwitchRequested = 0; // +0x98
    std::uint8_t mUnknown99[0x03]{}; // +0x99
    std::int32_t playbackTimeBaseFrames = 0; // +0x9C
    std::int32_t playbackTimeVsyncAnchor = 0; // +0xA0
    std::int32_t playbackTimeDeltaFrames = 0; // +0xA4
    std::uint8_t linkSwitchActive = 0; // +0xA8
    std::uint8_t mUnknownA9[0x17]{}; // +0xA9
    std::int32_t streamDecodeWindowState = 0; // +0xC0

    [[nodiscard]] AdxtDestroyableHandle*& SourceChannelRingLane(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x18 + (lane * sizeof(void*)));
    }

    [[nodiscard]] AdxtDestroyableHandle*& AuxReleaseLaneA(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x78 + (lane * sizeof(void*)));
    }

    [[nodiscard]] AdxtDestroyableHandle*& AuxReleaseLaneB(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<AdxtDestroyableHandle**>(base + 0x80 + (lane * sizeof(void*)));
    }

    [[nodiscard]] void*& SeamlessLscHandle()
    {
      return linkControlHandle;
    }

    [[nodiscard]] const void* SeamlessLscHandle() const
    {
      return linkControlHandle;
    }

    [[nodiscard]] char*& SeamlessAfsNameBuffer()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<char**>(base + 0xAC);
    }

    [[nodiscard]] std::int16_t& SeamlessFlowSectorHint()
    {
      return seamlessFlowSectorHint;
    }

    [[nodiscard]] std::int16_t& StreamBufferSectorLimitHint()
    {
      return streamBufferSectorLimitHint;
    }

    [[nodiscard]] std::int32_t& ErrorCheckFrameWindow()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int32_t*>(base + 0x38);
    }

    [[nodiscard]] std::int32_t& TransposeScaleDivisor()
    {
      return ErrorCheckFrameWindow();
    }

    [[nodiscard]] std::int16_t& ErrorStateCode()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x60);
    }

    [[nodiscard]] std::int32_t& LastDecodedSampleCount()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int32_t*>(base + 0x64);
    }

    [[nodiscard]] std::int16_t& DecodeStallCounter()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x68);
    }

    [[nodiscard]] std::int16_t& RecoveryWatchdogCounter()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x6A);
    }

    [[nodiscard]] std::uint8_t& StreamLoopSeekOnEosFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x6C);
    }

    [[nodiscard]] std::uint8_t& ErrorRecoveryMode()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x6D);
    }

    [[nodiscard]] std::uint8_t& ErrorCheckSuppressedFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x72);
    }

    [[nodiscard]] std::int32_t& StreamStartScratchWord()
    {
      return streamStartScratchWord;
    }

    [[nodiscard]] std::int32_t& LoopCount()
    {
      return streamStartScratchWord;
    }

    [[nodiscard]] std::int32_t& TransposeDecodeWindowSamples()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int32_t*>(base + 0x48);
    }

    [[nodiscard]] std::uint8_t& WaitPlayStartFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x70);
    }

    [[nodiscard]] std::uint8_t& ReadyPlayStartFlag()
    {
      return streamStartLatchByte;
    }

    [[nodiscard]] std::uint8_t& PauseStateFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0x72);
    }

    [[nodiscard]] std::uint8_t& StreamStartLatchByte()
    {
      return streamStartLatchByte;
    }

    [[nodiscard]] std::int32_t& StreamEndSector()
    {
      return streamEndSector;
    }

    [[nodiscard]] std::int32_t& StreamLoopStartSample()
    {
      return streamLoopStartSample;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeBaseFrames()
    {
      return playbackTimeBaseFrames;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeVsyncAnchor()
    {
      return playbackTimeVsyncAnchor;
    }

    [[nodiscard]] std::int32_t& PlaybackTimeDeltaFrames()
    {
      return playbackTimeDeltaFrames;
    }

    [[nodiscard]] std::uint8_t& DefaultPanSeedEnabled()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0xA9);
    }

    [[nodiscard]] std::uint8_t& AinfSwitchFlag()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *(base + 0xA9);
    }

    [[nodiscard]] const std::uint8_t& AinfSwitchFlag() const
    {
      const auto* const base = reinterpret_cast<const std::uint8_t*>(this);
      return *(base + 0xA9);
    }

    [[nodiscard]] std::int16_t& RequestedPanLane(const std::int32_t lane)
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x42 + (lane * static_cast<std::int32_t>(sizeof(std::int16_t))));
    }

    [[nodiscard]] const std::int16_t& RequestedPanLane(const std::int32_t lane) const
    {
      const auto* const base = reinterpret_cast<const std::uint8_t*>(this);
      return *reinterpret_cast<const std::int16_t*>(
        base + 0x42 + (lane * static_cast<std::int32_t>(sizeof(std::int16_t)))
      );
    }

    [[nodiscard]] std::int16_t& OutputVolumeLevel()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x40);
    }

    [[nodiscard]] const std::int16_t& OutputVolumeLevel() const
    {
      const auto* const base = reinterpret_cast<const std::uint8_t*>(this);
      return *reinterpret_cast<const std::int16_t*>(base + 0x40);
    }

    [[nodiscard]] std::int16_t& OutputBalanceLevel()
    {
      auto* const base = reinterpret_cast<std::uint8_t*>(this);
      return *reinterpret_cast<std::int16_t*>(base + 0x46);
    }

    [[nodiscard]] const std::int16_t& OutputBalanceLevel() const
    {
      const auto* const base = reinterpret_cast<const std::uint8_t*>(this);
      return *reinterpret_cast<const std::int16_t*>(base + 0x46);
    }

    [[nodiscard]] std::int32_t& StreamDecodeWindowState()
    {
      return streamDecodeWindowState;
    }
  };

  static_assert(offsetof(AdxtRuntimeState, used) == 0x00, "AdxtRuntimeState::used offset must be 0x00");
  static_assert(
    offsetof(AdxtRuntimeState, maxChannelCount) == 0x03, "AdxtRuntimeState::maxChannelCount offset must be 0x03"
  );
  static_assert(offsetof(AdxtRuntimeState, sjdHandle) == 0x04, "AdxtRuntimeState::sjdHandle offset must be 0x04");
  static_assert(offsetof(AdxtRuntimeState, streamHandle) == 0x08, "AdxtRuntimeState::streamHandle offset must be 0x08");
  static_assert(offsetof(AdxtRuntimeState, rnaHandle) == 0x0C, "AdxtRuntimeState::rnaHandle offset must be 0x0C");
  static_assert(
    offsetof(AdxtRuntimeState, sourceRingHandle) == 0x10, "AdxtRuntimeState::sourceRingHandle offset must be 0x10"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamJoinInputHandle) == 0x14,
    "AdxtRuntimeState::streamJoinInputHandle offset must be 0x14"
  );
  static_assert(
    offsetof(AdxtRuntimeState, mUnknown18) == 0x18, "AdxtRuntimeState::mUnknown18 offset must be 0x18"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamBufferSectorLimitHint) == 0x3C,
    "AdxtRuntimeState::streamBufferSectorLimitHint offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, seamlessFlowSectorHint) == 0x3E,
    "AdxtRuntimeState::seamlessFlowSectorHint offset must be 0x3E"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamStartScratchWord) == 0x4C,
    "AdxtRuntimeState::streamStartScratchWord offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamStartLatchByte) == 0x71,
    "AdxtRuntimeState::streamStartLatchByte offset must be 0x71"
  );
  static_assert(
    offsetof(AdxtRuntimeState, channelExpandHandle) == 0x74,
    "AdxtRuntimeState::channelExpandHandle offset must be 0x74"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkReadCursor) == 0x88, "AdxtRuntimeState::linkReadCursor offset must be 0x88"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamEndSector) == 0x8C, "AdxtRuntimeState::streamEndSector offset must be 0x8C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, streamLoopStartSample) == 0x90,
    "AdxtRuntimeState::streamLoopStartSample offset must be 0x90"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkControlHandle) == 0x94,
    "AdxtRuntimeState::linkControlHandle offset must be 0x94"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkSwitchRequested) == 0x98,
    "AdxtRuntimeState::linkSwitchRequested offset must be 0x98"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeBaseFrames) == 0x9C,
    "AdxtRuntimeState::playbackTimeBaseFrames offset must be 0x9C"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeVsyncAnchor) == 0xA0,
    "AdxtRuntimeState::playbackTimeVsyncAnchor offset must be 0xA0"
  );
  static_assert(
    offsetof(AdxtRuntimeState, playbackTimeDeltaFrames) == 0xA4,
    "AdxtRuntimeState::playbackTimeDeltaFrames offset must be 0xA4"
  );
  static_assert(
    offsetof(AdxtRuntimeState, linkSwitchActive) == 0xA8,
    "AdxtRuntimeState::linkSwitchActive offset must be 0xA8"
  );
  static_assert(offsetof(AdxtRuntimeState, mUnknownA9) == 0xA9, "AdxtRuntimeState::mUnknownA9 offset must be 0xA9");
  static_assert(
    offsetof(AdxtRuntimeState, streamDecodeWindowState) == 0xC0,
    "AdxtRuntimeState::streamDecodeWindowState offset must be 0xC0"
  );
  static_assert(sizeof(AdxtRuntimeState) == 0xC4, "AdxtRuntimeState size must be 0xC4");
  constexpr std::size_t kAdxtRuntimeSlotCount = 0x20;
  static_assert(
    (sizeof(AdxtRuntimeState) * kAdxtRuntimeSlotCount) == 0x1880,
    "ADXT runtime slot pool size must be 0x1880 bytes"
  );
  std::array<AdxtRuntimeState, kAdxtRuntimeSlotCount> gAdxtRuntimePool{};

  struct MwsfdPicUserBufferDescriptor
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t bufferBytes = 0; // +0x04
    std::int32_t bytesPerFrame = 0; // +0x08
  };

  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bufferAddress) == 0x00,
    "MwsfdPicUserBufferDescriptor::bufferAddress offset must be 0x00"
  );
  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bufferBytes) == 0x04,
    "MwsfdPicUserBufferDescriptor::bufferBytes offset must be 0x04"
  );
  static_assert(
    offsetof(MwsfdPicUserBufferDescriptor, bytesPerFrame) == 0x08,
    "MwsfdPicUserBufferDescriptor::bytesPerFrame offset must be 0x08"
  );
  static_assert(sizeof(MwsfdPicUserBufferDescriptor) == 0x0C, "MwsfdPicUserBufferDescriptor size must be 0x0C");

  struct MwsfdPlaybackPicUserView
  {
    std::uint8_t mUnknown00[0x178]{};
    MwsfdPicUserBufferDescriptor* picUserBuffer = nullptr; // +0x178
  };

  static_assert(
    offsetof(MwsfdPlaybackPicUserView, picUserBuffer) == 0x178,
    "MwsfdPlaybackPicUserView::picUserBuffer offset must be 0x178"
  );

  struct AdxfRuntimeHandleView
  {
    std::uint8_t used = 0; // +0x00
    std::uint8_t status = 0; // +0x01
    std::uint8_t sjFlag = 0; // +0x02
    std::uint8_t stopWithoutNetworkFlag = 0; // +0x03
    void* streamHandle = nullptr; // +0x04
    moho::SofdecSjSupplyHandle* sourceJoinObject = nullptr; // +0x08
    std::int32_t fileSizeSectors = 0; // +0x0C
    std::int32_t fileSizeBytes = 0; // +0x10
    std::int32_t readStartSector = 0; // +0x14
    std::int32_t requestSectorStart = 0; // +0x18
    std::int32_t requestSectorCount = 0; // +0x1C
    std::int32_t readProgressSectors = 0; // +0x20
    std::int32_t ocbiCallbackArg0 = 0; // +0x24
    std::int32_t ocbiCallbackArg1 = 0; // +0x28
    std::int32_t requestedReadSizeSectors = 0; // +0x2C
    std::int32_t fileStartSector = 0; // +0x30
    std::int32_t fileStartOffset = 0; // +0x34
    const char* boundFileName = nullptr; // +0x38
    std::int32_t boundRangeStartSector = 0; // +0x3C
    std::int32_t boundRangeSectorCount = 0; // +0x40
  };

  static_assert(offsetof(AdxfRuntimeHandleView, used) == 0x00, "AdxfRuntimeHandleView::used offset must be 0x00");
  static_assert(
    offsetof(AdxfRuntimeHandleView, status) == 0x01,
    "AdxfRuntimeHandleView::status offset must be 0x01"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, sjFlag) == 0x02,
    "AdxfRuntimeHandleView::sjFlag offset must be 0x02"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, stopWithoutNetworkFlag) == 0x03,
    "AdxfRuntimeHandleView::stopWithoutNetworkFlag offset must be 0x03"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, streamHandle) == 0x04,
    "AdxfRuntimeHandleView::streamHandle offset must be 0x04"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, sourceJoinObject) == 0x08,
    "AdxfRuntimeHandleView::sourceJoinObject offset must be 0x08"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, fileSizeSectors) == 0x0C,
    "AdxfRuntimeHandleView::fileSizeSectors offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, fileSizeBytes) == 0x10,
    "AdxfRuntimeHandleView::fileSizeBytes offset must be 0x10"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, readStartSector) == 0x14,
    "AdxfRuntimeHandleView::readStartSector offset must be 0x14"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestSectorStart) == 0x18,
    "AdxfRuntimeHandleView::requestSectorStart offset must be 0x18"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestSectorCount) == 0x1C,
    "AdxfRuntimeHandleView::requestSectorCount offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, readProgressSectors) == 0x20,
    "AdxfRuntimeHandleView::readProgressSectors offset must be 0x20"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, ocbiCallbackArg0) == 0x24,
    "AdxfRuntimeHandleView::ocbiCallbackArg0 offset must be 0x24"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, ocbiCallbackArg1) == 0x28,
    "AdxfRuntimeHandleView::ocbiCallbackArg1 offset must be 0x28"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, requestedReadSizeSectors) == 0x2C,
    "AdxfRuntimeHandleView::requestedReadSizeSectors offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, fileStartSector) == 0x30,
    "AdxfRuntimeHandleView::fileStartSector offset must be 0x30"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, fileStartOffset) == 0x34,
    "AdxfRuntimeHandleView::fileStartOffset offset must be 0x34"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, boundFileName) == 0x38,
    "AdxfRuntimeHandleView::boundFileName offset must be 0x38"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, boundRangeStartSector) == 0x3C,
    "AdxfRuntimeHandleView::boundRangeStartSector offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxfRuntimeHandleView, boundRangeSectorCount) == 0x40,
    "AdxfRuntimeHandleView::boundRangeSectorCount offset must be 0x40"
  );
  static_assert(sizeof(AdxfRuntimeHandleView) == 0x44, "AdxfRuntimeHandleView size must be 0x44");

  struct AdxfPointInfoRuntimeView
  {
    std::int32_t mUnknown00 = 0; // +0x00
    std::int32_t pointInfoSizeBytes = 0; // +0x04
    std::int32_t fileCount = 0; // +0x08
    std::array<std::uint8_t, 4> tableFlags{}; // +0x0C
    std::array<char, 0x100> archiveFileName{}; // +0x10
    std::int32_t fileStartOffsetBytes = 0; // +0x110
    std::int32_t rangeBase = 0; // +0x114
    union
    {
      struct
      {
        std::uint16_t rangeSeed16;
        std::uint16_t firstRangeLength16;
      };
      struct
      {
        std::int32_t rangeSeed32;
        std::int32_t firstRangeLength32;
      };
    } rangeTableHeader{}; // +0x118

    [[nodiscard]] bool UsesWideRangeTable() const
    {
      return tableFlags[3] == 1u;
    }

    [[nodiscard]] const std::int32_t* RangeLengths32() const
    {
      return &rangeTableHeader.firstRangeLength32;
    }

    [[nodiscard]] const std::uint16_t* RangeLengths16() const
    {
      return &rangeTableHeader.firstRangeLength16;
    }
  };

  static_assert(
    offsetof(AdxfPointInfoRuntimeView, pointInfoSizeBytes) == 0x04,
    "AdxfPointInfoRuntimeView::pointInfoSizeBytes offset must be 0x04"
  );
  static_assert(
    offsetof(AdxfPointInfoRuntimeView, fileCount) == 0x08,
    "AdxfPointInfoRuntimeView::fileCount offset must be 0x08"
  );
  static_assert(
    offsetof(AdxfPointInfoRuntimeView, archiveFileName) == 0x10,
    "AdxfPointInfoRuntimeView::archiveFileName offset must be 0x10"
  );
  static_assert(
    offsetof(AdxfPointInfoRuntimeView, fileStartOffsetBytes) == 0x110,
    "AdxfPointInfoRuntimeView::fileStartOffsetBytes offset must be 0x110"
  );
  static_assert(
    offsetof(AdxfPointInfoRuntimeView, rangeBase) == 0x114,
    "AdxfPointInfoRuntimeView::rangeBase offset must be 0x114"
  );
  static_assert(
    offsetof(AdxfPointInfoRuntimeView, rangeTableHeader) == 0x118,
    "AdxfPointInfoRuntimeView::rangeTableHeader offset must be 0x118"
  );

  constexpr std::size_t kAdxfHandleCount = 16;
  constexpr std::size_t kAdxfPointInfoCount = 256;
  constexpr std::size_t kAdxfCommandHistoryCount = 16;
  constexpr char kAdxfBuildVersion[] = "\nADXF/PC Ver.7.30 Build:Feb 28 2005 21:29:06\n";

  struct AdxfCommandHistoryEntry
  {
    std::uint8_t commandId = 0; // +0x00
    std::uint8_t commandStage = 0; // +0x01
    std::uint16_t callCount = 0; // +0x02
    std::int32_t argument0 = 0; // +0x04
    std::int32_t argument1 = 0; // +0x08
    std::int32_t argument2 = 0; // +0x0C
  };

  static_assert(offsetof(AdxfCommandHistoryEntry, commandId) == 0x00, "AdxfCommandHistoryEntry::commandId offset must be 0x00");
  static_assert(
    offsetof(AdxfCommandHistoryEntry, commandStage) == 0x01,
    "AdxfCommandHistoryEntry::commandStage offset must be 0x01"
  );
  static_assert(offsetof(AdxfCommandHistoryEntry, callCount) == 0x02, "AdxfCommandHistoryEntry::callCount offset must be 0x02");
  static_assert(offsetof(AdxfCommandHistoryEntry, argument0) == 0x04, "AdxfCommandHistoryEntry::argument0 offset must be 0x04");
  static_assert(offsetof(AdxfCommandHistoryEntry, argument1) == 0x08, "AdxfCommandHistoryEntry::argument1 offset must be 0x08");
  static_assert(offsetof(AdxfCommandHistoryEntry, argument2) == 0x0C, "AdxfCommandHistoryEntry::argument2 offset must be 0x0C");
  static_assert(sizeof(AdxfCommandHistoryEntry) == 0x10, "AdxfCommandHistoryEntry size must be 0x10");

  std::int32_t gAdxfInitCount = 0;
  const char* gCriVersionStringAdxf = nullptr;
  std::array<AdxfRuntimeHandleView, kAdxfHandleCount> gAdxfHandlePool{};
  std::array<AdxfPointInfoRuntimeView*, kAdxfPointInfoCount> gAdxfPointInfoById{};
  std::array<AdxfCommandHistoryEntry, kAdxfCommandHistoryCount> gAdxfCommandHistory{};
  std::array<std::uint16_t, 16> gAdxfCommandCallCountById{};
  std::int32_t gAdxfHistoryWriteIndex = 0;
  std::int32_t gAdxfOcbiEnabled = 0;
  std::array<std::uint8_t, 0x800> gAdxfPartitionLoadBuffer{};
  std::int32_t gAdxfCurrentFileIndex = 0;
  std::int32_t gAdxfLoadedPointNetworkHandle = 0;
  std::int32_t gAdxfLoadedPointId = -1;
  std::int32_t gAdxfLoadedPointReadSectors = 0;
  std::int32_t gAdxfLoadedPointLastStatus = 1;

  struct AdxsjdRuntimeView
  {
    std::uint8_t used = 0; // +0x00
    std::int8_t streamFormatClass = 0; // +0x01
    std::uint8_t outputHandleCount = 0; // +0x02
    std::uint8_t decodeExecState = 0; // +0x03
    moho::AdxBitstreamDecoderState* adxbHandle = nullptr; // +0x04
    void* inputSourceHandle = nullptr; // +0x08
    AdxsjdOutputHandle* outputHandles[4]{}; // +0x0C
    SjChunkRange outputWriteChunks[2]{}; // +0x1C
    std::int32_t decodedSampleCount = 0; // +0x2C
    std::int32_t decodedDataLengthBytes = 0; // +0x30
    std::int32_t decodePositionSamples = 0; // +0x34
    std::int32_t maxDecodeSamples = 0; // +0x38
    std::int32_t trapSampleCount = 0; // +0x3C
    std::int32_t trapCount = 0; // +0x40
    std::int32_t trapDataLengthBytes = 0; // +0x44
    void* trapCallback = nullptr; // +0x48
    std::int32_t trapCallbackContext = 0; // +0x4C
    void* filterCallback = nullptr; // +0x50
    std::int32_t filterCallbackContext = 0; // +0x54
    std::uint8_t spsdInfoState[0x40]{}; // +0x58
    std::int32_t headerLengthBytes = 0; // +0x98
    std::int32_t linkSwitchEnabled = 0; // +0x9C
    std::int32_t positiveSampleAdjust = 0; // +0xA0
    std::int32_t negativeSampleAdjust = 0; // +0xA4

    [[nodiscard]] moho::AdxBitstreamDecoderState* Decoder() const
    {
      return adxbHandle;
    }

    [[nodiscard]] std::int32_t OutputChannelCount() const
    {
      return static_cast<std::int32_t>(outputHandleCount);
    }

    [[nodiscard]] AdxsjdOutputHandle*& OutputHandle(const std::int32_t lane)
    {
      return outputHandles[lane];
    }
  };

  static_assert(offsetof(AdxsjdRuntimeView, used) == 0x00, "AdxsjdRuntimeView::used offset must be 0x00");
  static_assert(
    offsetof(AdxsjdRuntimeView, streamFormatClass) == 0x01,
    "AdxsjdRuntimeView::streamFormatClass offset must be 0x01"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, outputHandleCount) == 0x02,
    "AdxsjdRuntimeView::outputHandleCount offset must be 0x02"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, decodeExecState) == 0x03,
    "AdxsjdRuntimeView::decodeExecState offset must be 0x03"
  );
  static_assert(offsetof(AdxsjdRuntimeView, adxbHandle) == 0x04, "AdxsjdRuntimeView::adxbHandle offset must be 0x04");
  static_assert(
    offsetof(AdxsjdRuntimeView, inputSourceHandle) == 0x08,
    "AdxsjdRuntimeView::inputSourceHandle offset must be 0x08"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, outputHandles) == 0x0C,
    "AdxsjdRuntimeView::outputHandles offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, outputWriteChunks) == 0x1C,
    "AdxsjdRuntimeView::outputWriteChunks offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, decodedSampleCount) == 0x2C,
    "AdxsjdRuntimeView::decodedSampleCount offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, decodedDataLengthBytes) == 0x30,
    "AdxsjdRuntimeView::decodedDataLengthBytes offset must be 0x30"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, decodePositionSamples) == 0x34,
    "AdxsjdRuntimeView::decodePositionSamples offset must be 0x34"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, maxDecodeSamples) == 0x38,
    "AdxsjdRuntimeView::maxDecodeSamples offset must be 0x38"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, trapSampleCount) == 0x3C,
    "AdxsjdRuntimeView::trapSampleCount offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, trapCount) == 0x40,
    "AdxsjdRuntimeView::trapCount offset must be 0x40"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, trapDataLengthBytes) == 0x44,
    "AdxsjdRuntimeView::trapDataLengthBytes offset must be 0x44"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, trapCallback) == 0x48,
    "AdxsjdRuntimeView::trapCallback offset must be 0x48"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, trapCallbackContext) == 0x4C,
    "AdxsjdRuntimeView::trapCallbackContext offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, filterCallback) == 0x50,
    "AdxsjdRuntimeView::filterCallback offset must be 0x50"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, filterCallbackContext) == 0x54,
    "AdxsjdRuntimeView::filterCallbackContext offset must be 0x54"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, headerLengthBytes) == 0x98,
    "AdxsjdRuntimeView::headerLengthBytes offset must be 0x98"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, linkSwitchEnabled) == 0x9C,
    "AdxsjdRuntimeView::linkSwitchEnabled offset must be 0x9C"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, positiveSampleAdjust) == 0xA0,
    "AdxsjdRuntimeView::positiveSampleAdjust offset must be 0xA0"
  );
  static_assert(
    offsetof(AdxsjdRuntimeView, negativeSampleAdjust) == 0xA4,
    "AdxsjdRuntimeView::negativeSampleAdjust offset must be 0xA4"
  );
  static_assert(sizeof(AdxsjdRuntimeView) == 0xA8, "AdxsjdRuntimeView size must be 0xA8");

  AdxsjdRuntimeView gAdxsjdObjectPool[kAdxsjdObjectCount]{};
  std::int32_t gAdxsjdInitCount = 0;

  struct AdxrnaPanDispatchTable
  {
    std::uintptr_t mUnknown00 = 0; // +0x00
    std::uintptr_t mUnknown04 = 0; // +0x04
    std::uintptr_t mUnknown08 = 0; // +0x08
    void(__cdecl* destroyOutput)(void* outputOwner) = nullptr; // +0x0C
    std::int32_t(__cdecl* startPlayback)(void* outputOwner) = nullptr; // +0x10
    std::int32_t(__cdecl* pausePlayback)(void* outputOwner) = nullptr; // +0x14
    std::uintptr_t mUnknown18 = 0; // +0x18
    void(__cdecl* setChannelCount)(void* outputOwner, std::int32_t channelCount) = nullptr; // +0x1C
    std::int32_t(__cdecl* queryTransferReadCursor)(void* outputOwner, std::int32_t laneIndex) = nullptr; // +0x20
    std::uintptr_t mUnknown24 = 0; // +0x24
    std::int32_t(__cdecl* getSampleRateBase)(void* outputOwner) = nullptr; // +0x28
    std::int32_t(__cdecl* setBitsPerSample)(void* outputOwner, std::int32_t bitsPerSample) = nullptr; // +0x2C
    std::int32_t(__cdecl* getBitsPerSample)(void* outputOwner) = nullptr; // +0x30
    void(__cdecl* setOutputVolume)(void* outputOwner, std::int32_t volume) = nullptr; // +0x34
    std::int32_t(__cdecl* getOutputVolume)(void* outputOwner) = nullptr; // +0x38
    std::int32_t(__cdecl* setOutputPan)(void* outputOwner, std::int32_t channelIndex, std::int32_t panLevel) = nullptr; // +0x3C
    std::int32_t(__cdecl* getIndexedWord)(void* outputOwner, std::int32_t laneIndex) = nullptr; // +0x40
    std::int32_t(__cdecl* setOutputBalance)(void* outputOwner, std::int32_t balance) = nullptr; // +0x44
    std::uintptr_t mUnknown48 = 0; // +0x48
    std::int32_t(__cdecl* setLaneWordPair)(void* outputOwner, std::int32_t laneIndex, std::int32_t word0, std::int32_t word1) =
      nullptr; // +0x4C
    void(__cdecl* queryLaneWordPair)(void* outputOwner, std::int32_t laneIndex, std::int32_t* outWord0, std::int32_t* outWord1) =
      nullptr; // +0x50
    std::uintptr_t mUnknown54 = 0; // +0x54
    std::int32_t(__cdecl* stopPlayback)(void* outputOwner, std::int32_t stopMode) = nullptr; // +0x58
    std::int32_t(__cdecl* isChannelStopped)(void* outputOwner, std::int32_t channelIndex) = nullptr; // +0x5C
    std::int32_t(__cdecl* consumeTransferUnits)(
      void* outputOwner,
      std::int32_t requestedUnits,
      std::int32_t* outConsumedUnits
    ) = nullptr; // +0x60
  };

  static_assert(
    offsetof(AdxrnaPanDispatchTable, destroyOutput) == 0x0C,
    "AdxrnaPanDispatchTable::destroyOutput offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, startPlayback) == 0x10,
    "AdxrnaPanDispatchTable::startPlayback offset must be 0x10"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, pausePlayback) == 0x14,
    "AdxrnaPanDispatchTable::pausePlayback offset must be 0x14"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setChannelCount) == 0x1C,
    "AdxrnaPanDispatchTable::setChannelCount offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, queryTransferReadCursor) == 0x20,
    "AdxrnaPanDispatchTable::queryTransferReadCursor offset must be 0x20"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, getSampleRateBase) == 0x28,
    "AdxrnaPanDispatchTable::getSampleRateBase offset must be 0x28"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setBitsPerSample) == 0x2C,
    "AdxrnaPanDispatchTable::setBitsPerSample offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, getBitsPerSample) == 0x30,
    "AdxrnaPanDispatchTable::getBitsPerSample offset must be 0x30"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setOutputVolume) == 0x34,
    "AdxrnaPanDispatchTable::setOutputVolume offset must be 0x34"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, getOutputVolume) == 0x38,
    "AdxrnaPanDispatchTable::getOutputVolume offset must be 0x38"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setOutputPan) == 0x3C,
    "AdxrnaPanDispatchTable::setOutputPan offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, getIndexedWord) == 0x40,
    "AdxrnaPanDispatchTable::getIndexedWord offset must be 0x40"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setOutputBalance) == 0x44,
    "AdxrnaPanDispatchTable::setOutputBalance offset must be 0x44"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, setLaneWordPair) == 0x4C,
    "AdxrnaPanDispatchTable::setLaneWordPair offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, queryLaneWordPair) == 0x50,
    "AdxrnaPanDispatchTable::queryLaneWordPair offset must be 0x50"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, stopPlayback) == 0x58,
    "AdxrnaPanDispatchTable::stopPlayback offset must be 0x58"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, isChannelStopped) == 0x5C,
    "AdxrnaPanDispatchTable::isChannelStopped offset must be 0x5C"
  );
  static_assert(
    offsetof(AdxrnaPanDispatchTable, consumeTransferUnits) == 0x60,
    "AdxrnaPanDispatchTable::consumeTransferUnits offset must be 0x60"
  );

  struct AdxrnaOutputRuntimeView
  {
    AdxrnaPanDispatchTable* dispatchTable = nullptr; // +0x00
  };

  struct AdxrnaRuntimeView
  {
    std::uint8_t inUse = 0; // +0x00
    std::uint8_t mUnknown01 = 0; // +0x01
    std::uint8_t maxChannelCount = 0; // +0x02
    std::uint8_t channelCount = 0; // +0x03
    std::uint8_t mUnknown04[0x34]{}; // +0x04
    AdxrnaOutputRuntimeView* outputRuntime = nullptr; // +0x38
    std::uint8_t mUnknown3C[0x28]{}; // +0x3C
    std::int32_t outputPanByChannel[16]{}; // +0x64
  };

  static_assert(offsetof(AdxrnaRuntimeView, maxChannelCount) == 0x02, "AdxrnaRuntimeView::maxChannelCount offset must be 0x02");
  static_assert(offsetof(AdxrnaRuntimeView, channelCount) == 0x03, "AdxrnaRuntimeView::channelCount offset must be 0x03");
  static_assert(
    offsetof(AdxrnaRuntimeView, outputRuntime) == 0x38,
    "AdxrnaRuntimeView::outputRuntime offset must be 0x38"
  );
  static_assert(
    offsetof(AdxrnaRuntimeView, outputPanByChannel) == 0x64,
    "AdxrnaRuntimeView::outputPanByChannel offset must be 0x64"
  );

  struct AdxrnaTransportRuntimeView
  {
    std::uint8_t inUse = 0; // +0x00
    std::uint8_t stateFlags = 0; // +0x01
    std::uint8_t maxChannelCount = 0; // +0x02
    std::uint8_t channelCount = 0; // +0x03
    std::uint8_t transportResetState = 0; // +0x04
    std::uint8_t pendingTransferAck = 0; // +0x05
    std::uint8_t decodeControlFlags = 0; // +0x06
    std::uint8_t outputSyncPending = 0; // +0x07
    std::uint8_t mUnknown08_1F[0x18]{}; // +0x08
    void* channelJoinHandle0 = nullptr; // +0x20
    void* channelJoinHandle1 = nullptr; // +0x24
    std::int32_t transferRingSize = 0; // +0x28
    std::int32_t transferWritePosition = 0; // +0x2C
    std::int32_t transferReadPosition = 0; // +0x30
    std::int32_t queuedDataUnits = 0; // +0x34
    AdxrnaOutputRuntimeView* outputRuntime = nullptr; // +0x38
    std::int32_t pendingTransferUnits = 0; // +0x3C
    std::int32_t restoreWritePosition = 0; // +0x40
    std::int32_t restoreReadPosition = 0; // +0x44
    std::int32_t decodeCursorUnits = 0; // +0x48
    std::int32_t decodedDataUnits = 0; // +0x4C
    std::int32_t transferFreezePosition = 0; // +0x50
    std::int32_t transferAccumulatedUnits = 0; // +0x54
    std::int32_t transferCarryUnits = 0; // +0x58
    std::int32_t transferStopPending = 0; // +0x5C
    std::uint8_t mUnknown60_8B[0x2C]{}; // +0x60
    std::int32_t outputSyncStateWord = 0; // +0x8C
    std::int32_t transitionGuardFlag = 0; // +0x90
    std::uint8_t mUnknown94_97[0x04]{}; // +0x94
    std::int32_t serverPendingCount = 0; // +0x98
    std::uint8_t mUnknown9C_AF[0x14]{}; // +0x9C
  };

  static_assert(
    offsetof(AdxrnaTransportRuntimeView, stateFlags) == 0x01,
    "AdxrnaTransportRuntimeView::stateFlags offset must be 0x01"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transportResetState) == 0x04,
    "AdxrnaTransportRuntimeView::transportResetState offset must be 0x04"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, pendingTransferAck) == 0x05,
    "AdxrnaTransportRuntimeView::pendingTransferAck offset must be 0x05"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, decodeControlFlags) == 0x06,
    "AdxrnaTransportRuntimeView::decodeControlFlags offset must be 0x06"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, outputSyncPending) == 0x07,
    "AdxrnaTransportRuntimeView::outputSyncPending offset must be 0x07"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, channelCount) == 0x03,
    "AdxrnaTransportRuntimeView::channelCount offset must be 0x03"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferWritePosition) == 0x2C,
    "AdxrnaTransportRuntimeView::transferWritePosition offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferReadPosition) == 0x30,
    "AdxrnaTransportRuntimeView::transferReadPosition offset must be 0x30"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, queuedDataUnits) == 0x34,
    "AdxrnaTransportRuntimeView::queuedDataUnits offset must be 0x34"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, outputRuntime) == 0x38,
    "AdxrnaTransportRuntimeView::outputRuntime offset must be 0x38"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, pendingTransferUnits) == 0x3C,
    "AdxrnaTransportRuntimeView::pendingTransferUnits offset must be 0x3C"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, restoreWritePosition) == 0x40,
    "AdxrnaTransportRuntimeView::restoreWritePosition offset must be 0x40"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, restoreReadPosition) == 0x44,
    "AdxrnaTransportRuntimeView::restoreReadPosition offset must be 0x44"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, decodeCursorUnits) == 0x48,
    "AdxrnaTransportRuntimeView::decodeCursorUnits offset must be 0x48"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, decodedDataUnits) == 0x4C,
    "AdxrnaTransportRuntimeView::decodedDataUnits offset must be 0x4C"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferFreezePosition) == 0x50,
    "AdxrnaTransportRuntimeView::transferFreezePosition offset must be 0x50"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferAccumulatedUnits) == 0x54,
    "AdxrnaTransportRuntimeView::transferAccumulatedUnits offset must be 0x54"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferCarryUnits) == 0x58,
    "AdxrnaTransportRuntimeView::transferCarryUnits offset must be 0x58"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transferStopPending) == 0x5C,
    "AdxrnaTransportRuntimeView::transferStopPending offset must be 0x5C"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, outputSyncStateWord) == 0x8C,
    "AdxrnaTransportRuntimeView::outputSyncStateWord offset must be 0x8C"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, transitionGuardFlag) == 0x90,
    "AdxrnaTransportRuntimeView::transitionGuardFlag offset must be 0x90"
  );
  static_assert(
    offsetof(AdxrnaTransportRuntimeView, serverPendingCount) == 0x98,
    "AdxrnaTransportRuntimeView::serverPendingCount offset must be 0x98"
  );
  static_assert(sizeof(AdxrnaTransportRuntimeView) == 0xB0, "AdxrnaTransportRuntimeView size must be 0xB0");

  struct AdxrnaDsoundHandlerDispatch
  {
    std::uintptr_t mUnknown00 = 0; // +0x00
    std::uintptr_t mUnknown04 = 0; // +0x04
    std::uintptr_t mUnknown08 = 0; // +0x08
    void(__cdecl* initialize)(IDirectSound8* directSound) = nullptr; // +0x0C
    void(__cdecl* shutdown)() = nullptr; // +0x10
    AdxrnaOutputRuntimeView*(__cdecl* createOutputRuntime)(std::int32_t channelCount) = nullptr; // +0x14
  };

  static_assert(
    offsetof(AdxrnaDsoundHandlerDispatch, initialize) == 0x0C,
    "AdxrnaDsoundHandlerDispatch::initialize offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxrnaDsoundHandlerDispatch, shutdown) == 0x10,
    "AdxrnaDsoundHandlerDispatch::shutdown offset must be 0x10"
  );
  static_assert(
    offsetof(AdxrnaDsoundHandlerDispatch, createOutputRuntime) == 0x14,
    "AdxrnaDsoundHandlerDispatch::createOutputRuntime offset must be 0x14"
  );

  struct AdxrnaPlaySwitchRuntimeView
  {
    std::uint8_t mUnknown00 = 0; // +0x00
    std::uint8_t stateFlags = 0; // +0x01
    std::uint8_t mUnknown02[0x92]{}; // +0x02
    std::int32_t playSwitch = 0; // +0x94
    std::int32_t appliedPlaySwitch = 0; // +0x98
    std::int32_t stopTransitionPending = 0; // +0x9C
  };

  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, stateFlags) == 0x01,
    "AdxrnaPlaySwitchRuntimeView::stateFlags offset must be 0x01"
  );
  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, playSwitch) == 0x94,
    "AdxrnaPlaySwitchRuntimeView::playSwitch offset must be 0x94"
  );
  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, appliedPlaySwitch) == 0x98,
    "AdxrnaPlaySwitchRuntimeView::appliedPlaySwitch offset must be 0x98"
  );
  static_assert(
    offsetof(AdxrnaPlaySwitchRuntimeView, stopTransitionPending) == 0x9C,
    "AdxrnaPlaySwitchRuntimeView::stopTransitionPending offset must be 0x9C"
  );

  struct AdxrnaLegacyMetricsRuntimeView
  {
    std::uint8_t mUnknown00_07[0x08]{}; // +0x00
    std::int32_t queuedDataCount = 0; // +0x08
    std::int32_t timeScaleBase = 0; // +0x0C
    std::uint8_t mUnknown10_5F[0x50]{}; // +0x10
    std::int32_t streamInfoWord60 = 0; // +0x60
    std::int32_t streamInfoWords64[2]{}; // +0x64
    std::int32_t streamInfoWord6C = 0; // +0x6C
    std::int32_t streamInfoWord70 = 0; // +0x70
    std::int32_t streamInfoWord74 = 0; // +0x74
    std::int32_t transposeOctaves = 0; // +0x78
    std::int32_t transposeCents = 0; // +0x7C
    std::int32_t streamHeaderLane3Word0 = 0; // +0x80
    std::int32_t streamHeaderLane3Word1 = 0; // +0x84
    std::int32_t streamInfoWord88 = 0; // +0x88
    std::uint8_t mUnknown8C_9F[0x14]{}; // +0x8C
    std::int32_t streamInfoWordA0 = 0; // +0xA0
    std::int32_t appliedOutputVolume = 0; // +0xA4
    std::int32_t calculatedSampleRate = 0; // +0xA8
    std::int32_t appliedSampleRate = 0; // +0xAC
  };

  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, queuedDataCount) == 0x08,
    "AdxrnaLegacyMetricsRuntimeView::queuedDataCount offset must be 0x08"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, timeScaleBase) == 0x0C,
    "AdxrnaLegacyMetricsRuntimeView::timeScaleBase offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWord60) == 0x60,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWord60 offset must be 0x60"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWords64) == 0x64,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWords64 offset must be 0x64"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWord6C) == 0x6C,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWord6C offset must be 0x6C"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWord70) == 0x70,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWord70 offset must be 0x70"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWord74) == 0x74,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWord74 offset must be 0x74"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, transposeOctaves) == 0x78,
    "AdxrnaLegacyMetricsRuntimeView::transposeOctaves offset must be 0x78"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, transposeCents) == 0x7C,
    "AdxrnaLegacyMetricsRuntimeView::transposeCents offset must be 0x7C"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamHeaderLane3Word0) == 0x80,
    "AdxrnaLegacyMetricsRuntimeView::streamHeaderLane3Word0 offset must be 0x80"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamHeaderLane3Word1) == 0x84,
    "AdxrnaLegacyMetricsRuntimeView::streamHeaderLane3Word1 offset must be 0x84"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWord88) == 0x88,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWord88 offset must be 0x88"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, streamInfoWordA0) == 0xA0,
    "AdxrnaLegacyMetricsRuntimeView::streamInfoWordA0 offset must be 0xA0"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, appliedOutputVolume) == 0xA4,
    "AdxrnaLegacyMetricsRuntimeView::appliedOutputVolume offset must be 0xA4"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, calculatedSampleRate) == 0xA8,
    "AdxrnaLegacyMetricsRuntimeView::calculatedSampleRate offset must be 0xA8"
  );
  static_assert(
    offsetof(AdxrnaLegacyMetricsRuntimeView, appliedSampleRate) == 0xAC,
    "AdxrnaLegacyMetricsRuntimeView::appliedSampleRate offset must be 0xAC"
  );

  struct AdxrnaStateControlRuntimeView
  {
    std::uint8_t mUnknown00 = 0; // +0x00
    std::uint8_t stateByte = 0; // +0x01
    std::uint8_t mUnknown02_43[0x42]{}; // +0x02
    std::int32_t flowLimitWord = 0; // +0x44
  };

  static_assert(
    offsetof(AdxrnaStateControlRuntimeView, stateByte) == 0x01,
    "AdxrnaStateControlRuntimeView::stateByte offset must be 0x01"
  );
  static_assert(
    offsetof(AdxrnaStateControlRuntimeView, flowLimitWord) == 0x44,
    "AdxrnaStateControlRuntimeView::flowLimitWord offset must be 0x44"
  );

  struct AdxtPanCacheRuntimeView
  {
    std::uint8_t mUnknown00[0x42]{}; // +0x00
    std::int16_t requestedPanByChannel[16]{}; // +0x42
  };

  static_assert(
    offsetof(AdxtPanCacheRuntimeView, requestedPanByChannel) == 0x42,
    "AdxtPanCacheRuntimeView::requestedPanByChannel offset must be 0x42"
  );

  using SofdecReportCallback = std::int32_t(__cdecl*)(std::int32_t callbackContext, const char* message);
  using AdxtDestroyCallback = void(__cdecl*)(void* adxtRuntime);
  constexpr char kAdxtBuildVersion[] = "\nADXT/PC Ver.9.44 Build:Feb 28 2005 21:29:08\n";

  SofdecReportCallback gSofdecReportCallback = nullptr;
  std::int32_t gSofdecReportCallbackContext = 0;
  std::int32_t gSofdecDolbyAttachRefCount = 0;
  AdxtDestroyCallback gAdxtDestroyCallback = nullptr;
  std::int32_t gAdxtInitCount = 0;
  std::int32_t gAdxtVsyncServerEnabled = 0;
  std::int32_t gAdxtDefaultServerFrequency = 0;
  std::int32_t gAdxtLastServerFrequency = 0;
  std::int32_t gAdxtTimeMode = 0;
  std::int32_t gAdxtTimeToVsyncScale = 0;
  std::int32_t gAdxtVsyncCount = 0;
  std::int32_t gAdxtTimeAuxCounter = 0;
  std::int32_t gAdxtStreamEosSector = 0x7FFFFFFF;
  std::int32_t gAdxrnaPauseAllState = 0;
  std::int32_t gAdxcrsLevel = 0;
  std::int32_t gAdxcrsInitCount = 0;
  std::int32_t gSjCriticalSectionLevel = 0;
  std::int32_t gSjInitCount = 0;
  std::int32_t gAdxtFsServerEnterCount = 0;
  std::int32_t gAdxrnaInitCount = 0;
  IDirectSound8* gAdxrnaDirectSound8 = nullptr;
  constexpr std::size_t kAdxrnaRuntimeObjectCount = 32;
  std::array<AdxrnaTransportRuntimeView, kAdxrnaRuntimeObjectCount> gAdxrnaRuntimePool{};
  std::array<std::uint8_t, 0x820> gAdxrnaScratchStateA{};
  std::array<std::uint8_t, 0x800> gAdxrnaScratchStateB{};
  AdxrnaDsoundHandlerDispatch* gAdxrnaDsoundHandler = nullptr;
  std::int32_t gAdxrnaDestroyGuard = 0;
  std::int32_t gAdxrnaTransferDrainPollCount = 0;

  [[nodiscard]] std::uint8_t* AlignPointerTo4Bytes(std::uint8_t* pointer)
  {
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    const auto misalignment = static_cast<std::uint32_t>(address & 0x3u);
    if (misalignment == 0) {
      return pointer;
    }
    return pointer + (4u - misalignment);
  }

  [[nodiscard]] AdxbRuntimeView* AsAdxbRuntimeView(moho::AdxBitstreamDecoderState* const decoder)
  {
    return reinterpret_cast<AdxbRuntimeView*>(decoder);
  }

  [[nodiscard]] const AdxbRuntimeView* AsAdxbRuntimeView(const moho::AdxBitstreamDecoderState* const decoder)
  {
    return reinterpret_cast<const AdxbRuntimeView*>(decoder);
  }

  [[nodiscard]] AdxsjdRuntimeView* AsAdxsjdRuntimeView(const std::int32_t sjdHandle)
  {
    return reinterpret_cast<AdxsjdRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sjdHandle)));
  }

  [[nodiscard]] AdxrnaRuntimeView* AsAdxrnaRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaRuntimeView*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle)));
  }

  [[nodiscard]] AdxrnaTransportRuntimeView* AsAdxrnaTransportRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaTransportRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle))
    );
  }

  [[nodiscard]] AdxrnaPlaySwitchRuntimeView* AsAdxrnaPlaySwitchRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaPlaySwitchRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle))
    );
  }

  [[nodiscard]] AdxrnaLegacyMetricsRuntimeView* AsAdxrnaLegacyMetricsRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaLegacyMetricsRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle))
    );
  }

  [[nodiscard]] AdxrnaStateControlRuntimeView* AsAdxrnaStateControlRuntimeView(const std::int32_t rnaHandle)
  {
    return reinterpret_cast<AdxrnaStateControlRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(rnaHandle))
    );
  }

  namespace
  {
    void __cdecl AdxrnaDsoundNoOpInitialize(IDirectSound8*)
    {
    }

    void __cdecl AdxrnaDsoundNoOpShutdown()
    {
    }

    AdxrnaOutputRuntimeView* __cdecl AdxrnaDsoundNoOpCreateOutputRuntime(std::int32_t)
    {
      return nullptr;
    }

    AdxrnaDsoundHandlerDispatch gAdxrnaFallbackDsoundHandler{
      0,
      0,
      0,
      &AdxrnaDsoundNoOpInitialize,
      &AdxrnaDsoundNoOpShutdown,
      &AdxrnaDsoundNoOpCreateOutputRuntime
    };
  } // namespace

  /**
   * Address: 0x00B176C0 (FUN_00B176C0, sub_B176C0)
   *
   * What it does:
   * Returns default ADXRNA DirectSound handler dispatch table.
   */
  [[maybe_unused]] AdxrnaDsoundHandlerDispatch* adxrna_GetDefaultDsoundHandler()
  {
    return &gAdxrnaFallbackDsoundHandler;
  }

  /**
   * Address: 0x00B147A0 (FUN_00B147A0, nullsub_34)
   *
   * What it does:
   * Post-init no-op hook used by ADXRNA initialization flow.
   */
  [[maybe_unused]] void adxrna_PostInitNoOpHook()
  {
  }

  [[nodiscard]] std::int32_t ClampAdxrnaPanLevel(std::int32_t panLevel)
  {
    if (panLevel < -15) {
      return -15;
    }
    if (panLevel > 15) {
      return 15;
    }
    return panLevel;
  }

  [[nodiscard]] std::int32_t ClampAdxrnaFxLevel(std::int32_t level)
  {
    if (level < -45) {
      return -45;
    }
    if (level > 0) {
      return 0;
    }
    return level;
  }

  [[nodiscard]] std::int16_t ResolveAdxsjdDefaultPanLane(
    const std::int32_t sjdHandle,
    const std::int32_t channelIndex
  )
  {
    auto* const sjdRuntime = AsAdxsjdRuntimeView(sjdHandle);
    if (
      ADXB_GetAinfLen(sjdRuntime->adxbHandle) > 0
      && (sjdRuntime->streamFormatClass == 2u || sjdRuntime->streamFormatClass == 3u)
    ) {
      return ADXB_GetDefPan(sjdRuntime->adxbHandle, channelIndex);
    }
    return -128;
  }

  [[nodiscard]] std::int32_t ResolveAdxsjdChannelCount(const std::int32_t sjdHandle)
  {
    return ADXB_GetNumChan(AsAdxsjdRuntimeView(sjdHandle)->adxbHandle);
  }

  std::int32_t SetAdxrnaOutputPan(const std::int32_t rnaHandle, const std::int32_t channelIndex, const std::int32_t panLevel)
  {
    auto* const rnaRuntime = AsAdxrnaRuntimeView(rnaHandle);
    if (rnaRuntime == nullptr) {
      return ADXERR_CallErrFunc1_(kAdxrnaIllegalParameterMessage);
    }

    if (channelIndex < 0 || channelIndex >= static_cast<std::int32_t>(rnaRuntime->channelCount)) {
      return 0;
    }

    const std::int32_t clampedPan = ClampAdxrnaPanLevel(panLevel);
    const std::int32_t result =
      rnaRuntime->outputRuntime->dispatchTable->setOutputPan(rnaRuntime->outputRuntime, channelIndex, clampedPan);
    rnaRuntime->outputPanByChannel[channelIndex] = clampedPan;
    return result;
  }

  struct MwlRnaRuntimeView
  {
    std::uint8_t inUse = 0; // +0x00
    std::uint8_t stateFlags = 0; // +0x01
    std::uint8_t maxChannelCount = 0; // +0x02
    std::uint8_t channelCount = 0; // +0x03
    std::uint8_t transportResetState = 0; // +0x04
    std::uint8_t pendingTransferAck = 0; // +0x05
    std::uint8_t decodeControlFlags = 0; // +0x06
    std::uint8_t outputSyncPending = 0; // +0x07
    std::int32_t bitsPerSample = 0; // +0x08
    std::uint8_t mUnknown0C[0x14]{}; // +0x0C
    void* channelSjHandle0 = nullptr; // +0x20
    void* channelSjHandle1 = nullptr; // +0x24
    std::int32_t transferCapacityBytes = 0; // +0x28
    std::int32_t transferWriteCursor = 0; // +0x2C
    std::int32_t transferReadCursor = 0; // +0x30
    std::int32_t transferConsumedBytes = 0; // +0x34
    void* transferCallbackOwner = nullptr; // +0x38
    std::int32_t lastTransferUnits = 0; // +0x3C
    std::uint8_t mUnknown40_4F[0x10]{}; // +0x40
    std::int32_t transferFreezePosition = 0; // +0x50
    std::int32_t transferAccumulatedUnits = 0; // +0x54
    std::int32_t transferCarryUnits = 0; // +0x58
    std::int32_t transferIssuedFlag = 0; // +0x5C
  };

  static_assert(offsetof(MwlRnaRuntimeView, channelCount) == 0x03, "MwlRnaRuntimeView::channelCount offset must be 0x03");
  static_assert(
    offsetof(MwlRnaRuntimeView, pendingTransferAck) == 0x05,
    "MwlRnaRuntimeView::pendingTransferAck offset must be 0x05"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, outputSyncPending) == 0x07,
    "MwlRnaRuntimeView::outputSyncPending offset must be 0x07"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, bitsPerSample) == 0x08,
    "MwlRnaRuntimeView::bitsPerSample offset must be 0x08"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, channelSjHandle0) == 0x20,
    "MwlRnaRuntimeView::channelSjHandle0 offset must be 0x20"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, channelSjHandle1) == 0x24,
    "MwlRnaRuntimeView::channelSjHandle1 offset must be 0x24"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferCapacityBytes) == 0x28,
    "MwlRnaRuntimeView::transferCapacityBytes offset must be 0x28"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferWriteCursor) == 0x2C,
    "MwlRnaRuntimeView::transferWriteCursor offset must be 0x2C"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferReadCursor) == 0x30,
    "MwlRnaRuntimeView::transferReadCursor offset must be 0x30"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferConsumedBytes) == 0x34,
    "MwlRnaRuntimeView::transferConsumedBytes offset must be 0x34"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferCallbackOwner) == 0x38,
    "MwlRnaRuntimeView::transferCallbackOwner offset must be 0x38"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, lastTransferUnits) == 0x3C,
    "MwlRnaRuntimeView::lastTransferUnits offset must be 0x3C"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferFreezePosition) == 0x50,
    "MwlRnaRuntimeView::transferFreezePosition offset must be 0x50"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferAccumulatedUnits) == 0x54,
    "MwlRnaRuntimeView::transferAccumulatedUnits offset must be 0x54"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferCarryUnits) == 0x58,
    "MwlRnaRuntimeView::transferCarryUnits offset must be 0x58"
  );
  static_assert(
    offsetof(MwlRnaRuntimeView, transferIssuedFlag) == 0x5C,
    "MwlRnaRuntimeView::transferIssuedFlag offset must be 0x5C"
  );

  struct SjRuntimeChunkView
  {
    std::int32_t bufferAddress = 0; // +0x00
    std::int32_t byteCount = 0; // +0x04
  };

  static_assert(offsetof(SjRuntimeChunkView, bufferAddress) == 0x00, "SjRuntimeChunkView::bufferAddress offset must be 0x00");
  static_assert(offsetof(SjRuntimeChunkView, byteCount) == 0x04, "SjRuntimeChunkView::byteCount offset must be 0x04");
  static_assert(sizeof(SjRuntimeChunkView) == 0x08, "SjRuntimeChunkView size must be 0x08");

  using SjAcquireChunkFn = void(__cdecl*)(void* handle, std::int32_t lane, std::int32_t requestedBytes, SjRuntimeChunkView* outChunk);
  using SjSubmitChunkFn = void(__cdecl*)(void* handle, std::int32_t lane, SjRuntimeChunkView* chunk);
  using M2asjdStreamDestroyFn = void(__cdecl*)(M2asjdIoStream* stream);
  using RnaTransferDispatchFn =
    void(__cdecl*)(void* callbackOwner, std::int32_t channelIndex, std::int32_t startUnit, std::int32_t sourceAddress, std::int32_t transferUnits);

  [[nodiscard]] SjAcquireChunkFn ResolveSjAcquireChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjAcquireChunkFn>(vtable[6]); // +0x18
  }

  [[nodiscard]] SjSubmitChunkFn ResolveSjSubmitChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjSubmitChunkFn>(vtable[7]); // +0x1C
  }

  [[nodiscard]] SjSubmitChunkFn ResolveSjReturnChunkFn(void* const sjHandle)
  {
    auto** const vtable = *reinterpret_cast<void***>(sjHandle);
    return reinterpret_cast<SjSubmitChunkFn>(vtable[8]); // +0x20
  }

  [[nodiscard]] M2asjdStreamDestroyFn ResolveM2asjdStreamDestroyFn(M2asjdIoStream* const stream)
  {
    auto** const vtable = *reinterpret_cast<void***>(stream);
    return reinterpret_cast<M2asjdStreamDestroyFn>(vtable[3]); // +0x0C
  }

  [[nodiscard]] RnaTransferDispatchFn ResolveRnaTransferDispatchFn(void* const callbackOwner)
  {
    auto** const vtable = *reinterpret_cast<void***>(callbackOwner);
    return reinterpret_cast<RnaTransferDispatchFn>(vtable[21]); // +0x54
  }

  std::int32_t gMwlRnaChunkScratch0 = 0;
  std::int32_t gMwlRnaChunkScratch1 = 0;

  /**
   * Address: 0x00B15330 (FUN_00B15330, sub_B15330)
   *
   * What it does:
   * Dispatches one RNA transfer callback chunk and marks transfer-issued lane.
   */
  std::int32_t mwlRnaDispatchTransferChunk(
    MwlRnaRuntimeView* const runtime,
    const std::int32_t channelIndex,
    const std::int32_t startUnit,
    const std::int32_t sourceAddress,
    const std::int32_t transferUnits
  )
  {
    if (transferUnits <= 0) {
      return 0;
    }

    ResolveRnaTransferDispatchFn(runtime->transferCallbackOwner)(
      runtime->transferCallbackOwner,
      channelIndex,
      startUnit,
      sourceAddress,
      transferUnits
    );
    runtime->transferIssuedFlag = 1;
    return transferUnits;
  }

  /**
   * Address: 0x00B15160 (FUN_00B15160, mwlRnaStartTrans)
   *
   * What it does:
   * Pulls per-channel source chunks, computes aligned transferable unit count,
   * dispatches transfer callback lanes, then returns split chunks to SJ lanes.
   */
  std::int32_t mwlRnaStartTrans(MwlRnaRuntimeView* const runtime)
  {
    if (runtime == nullptr || runtime->bitsPerSample <= 0) {
      return 0;
    }

    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    if (channelCount <= 0) {
      return 0;
    }

    const std::int32_t unitStride = 8 * (32 / runtime->bitsPerSample);
    const std::int32_t availableTransferBytes = runtime->transferCapacityBytes - runtime->transferConsumedBytes;
    const std::int32_t maxTransferUnits = unitStride * (availableTransferBytes / unitStride);

    std::array<SjRuntimeChunkView, 2> sourceChunks{};
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
      if (sjHandle == nullptr) {
        CRIERR_CallErr(kMwlRnaStartTransNullSjMessage);
      }

      ResolveSjAcquireChunkFn(sjHandle)(
        sjHandle,
        1,
        (maxTransferUnits * runtime->bitsPerSample) / 8,
        &sourceChunks[static_cast<std::size_t>(channelIndex)]
      );
    }

    std::int32_t availableChunkBytes = sourceChunks[0].byteCount;
    if (channelCount != 1 && sourceChunks[0].byteCount >= sourceChunks[1].byteCount) {
      availableChunkBytes = sourceChunks[1].byteCount;
    }

    std::int32_t transferUnits = 8 * (availableChunkBytes / runtime->bitsPerSample);
    if (transferUnits >= maxTransferUnits) {
      transferUnits = maxTransferUnits;
    }

    const std::int32_t transferRoomBytes = runtime->transferCapacityBytes - runtime->transferWriteCursor;
    if (transferUnits >= transferRoomBytes) {
      transferUnits = transferRoomBytes;
    }

    transferUnits = unitStride * (transferUnits / unitStride);
    if (transferUnits > 0) {
      std::int32_t transferredUnits = 0;
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
        gMwlRnaChunkScratch0 = 0;
        transferredUnits = mwlRnaDispatchTransferChunk(
          runtime,
          channelIndex,
          runtime->transferWriteCursor,
          sourceChunks[static_cast<std::size_t>(channelIndex)].bufferAddress,
          transferUnits
        );
        gMwlRnaChunkScratch1 = 0;

        SjRuntimeChunkView headChunk{};
        SjRuntimeChunkView tailChunk{};
        SJ_SplitChunk(
          reinterpret_cast<moho::SjChunkRange*>(&sourceChunks[static_cast<std::size_t>(channelIndex)]),
          (transferredUnits * runtime->bitsPerSample) / 8,
          reinterpret_cast<moho::SjChunkRange*>(&headChunk),
          reinterpret_cast<moho::SjChunkRange*>(&tailChunk)
        );
        ResolveSjReturnChunkFn(sjHandle)(sjHandle, 0, &headChunk);
        ResolveSjSubmitChunkFn(sjHandle)(sjHandle, 1, &tailChunk);
      }

      runtime->lastTransferUnits = transferredUnits;
      return transferredUnits;
    }

    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      void* const sjHandle = (channelIndex == 0) ? runtime->channelSjHandle0 : runtime->channelSjHandle1;
      if (sjHandle == nullptr) {
        CRIERR_CallErr(kMwlRnaStartTransNullSjMessage);
      }

      ResolveSjSubmitChunkFn(sjHandle)(sjHandle, 1, &sourceChunks[static_cast<std::size_t>(channelIndex)]);
    }

    return 0;
  }

  /**
   * Address: 0x00B150A0 (FUN_00B150A0, nullsub_35)
   *
   * What it does:
   * Legacy ADXRNA per-tick no-op hook.
   */
  [[maybe_unused]] void adxrna_ExecTickNoOpHook()
  {
  }

  /**
   * Address: 0x00B150B0 (FUN_00B150B0, sub_B150B0)
   *
   * What it does:
   * Samples output transfer-read cursor, aligns it to transfer stride, then
   * reconciles queued/decode cursor lanes under RNA critical section.
   */
  [[maybe_unused]] void adxrna_UpdateTransferReadState(const std::int32_t rnaHandle)
  {
    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    auto* const mwlRuntime = reinterpret_cast<MwlRnaRuntimeView*>(runtime);

    const std::int32_t previousReadCursor = runtime->transferReadPosition;
    const std::int32_t outputReadCursor = runtime->outputRuntime->dispatchTable->queryTransferReadCursor(runtime->outputRuntime, 0);
    const std::int32_t transferUnitStride = 8 * (32 / mwlRuntime->bitsPerSample);

    CRICRS_Enter();

    const std::int32_t alignedReadCursor = transferUnitStride * (outputReadCursor / transferUnitStride);
    runtime->transferReadPosition = alignedReadCursor;

    std::int32_t consumedUnits = alignedReadCursor - previousReadCursor;
    if (consumedUnits < 0) {
      consumedUnits += runtime->transferRingSize;
    }

    const std::int32_t ringGuardThreshold = runtime->transferRingSize - (runtime->transferRingSize >> 4);
    if (consumedUnits > ringGuardThreshold && alignedReadCursor != 0) {
      runtime->transferReadPosition = previousReadCursor;
      consumedUnits = 0;
    }

    std::int32_t queuedUnits = runtime->queuedDataUnits - consumedUnits;
    if (queuedUnits < 0) {
      queuedUnits = 0;
      consumedUnits = runtime->transferWritePosition - previousReadCursor;
      if ((runtime->stateFlags & 0x01u) != 0u) {
        runtime->transportResetState = 1;
        runtime->restoreReadPosition = runtime->transferReadPosition;
      }
    }

    runtime->queuedDataUnits = queuedUnits;
    runtime->decodeCursorUnits += consumedUnits;

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B14ED0 (FUN_00B14ED0, _ADXRNA_ExecServer)
   *
   * What it does:
   * Runs one exec tick for each used ADXRNA runtime object in the global pool.
   */
  void ADXRNA_ExecServer()
  {
    for (auto& runtime : gAdxrnaRuntimePool) {
      if (runtime.inUse == 1u) {
        ADXRNA_ExecHndl(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&runtime)));
      }
    }
  }

  /**
   * Address: 0x00B14BC0 (FUN_00B14BC0, sub_B14BC0)
   *
   * What it does:
   * Sets decode-control pending byte lane (`+0x06`) on one RNA runtime.
   */
  [[maybe_unused]] AdxrnaTransportRuntimeView* adxrna_SetDecodeControlPending(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return nullptr;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    if (runtime->decodeControlFlags != 1u) {
      runtime->decodeControlFlags = 1u;
    }
    return runtime;
  }

  /**
   * Address: 0x00B14A10 (FUN_00B14A10, adxrna_next_obj)
   *
   * What it does:
   * Returns the first free ADXRNA runtime object from the global pool.
   */
  [[maybe_unused]] AdxrnaTransportRuntimeView* adxrna_GetNextFreeRuntimeObject()
  {
    for (auto& runtime : gAdxrnaRuntimePool) {
      if (runtime.inUse == 0u) {
        return &runtime;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B149A0 (FUN_00B149A0, sub_B149A0)
   *
   * What it does:
   * Resets one ADXRNA runtime object's transport/metrics control lanes to the
   * legacy create-time defaults.
   */
  [[maybe_unused]] AdxrnaTransportRuntimeView* adxrna_ResetRuntimeDefaults(AdxrnaTransportRuntimeView* const runtime)
  {
    runtime->stateFlags = 0;
    runtime->transportResetState = 0;
    runtime->pendingTransferAck = 0;
    runtime->decodeControlFlags = 0;
    runtime->queuedDataUnits = 0;
    runtime->transferWritePosition = 0;
    runtime->transferReadPosition = 0;
    runtime->restoreWritePosition = 0x2000;
    runtime->restoreReadPosition = 0x2000;
    runtime->decodeCursorUnits = 0;

    auto* const metricsRuntime = reinterpret_cast<AdxrnaLegacyMetricsRuntimeView*>(runtime);
    metricsRuntime->streamInfoWord60 = 0;
    metricsRuntime->streamInfoWord6C = 0;
    metricsRuntime->streamInfoWord70 = 0;
    metricsRuntime->streamInfoWord74 = -45;
    metricsRuntime->transposeOctaves = 0;
    metricsRuntime->transposeCents = 0;
    metricsRuntime->streamHeaderLane3Word0 = 0;
    metricsRuntime->streamHeaderLane3Word1 = 0;
    metricsRuntime->streamInfoWord88 = 0;

    runtime->transitionGuardFlag = 0;
    runtime->outputSyncPending = 0;
    runtime->outputSyncStateWord = 0;
    return runtime;
  }

  /**
   * Address: 0x00B14840 (FUN_00B14840, adxrna_SetGetTimeFunc)
   *
   * What it does:
   * Updates global ADXRNA microsecond time callback lane.
   */
  [[maybe_unused]] void adxrna_SetGetTimeFunc(std::int32_t(__cdecl* getTimeCallback)())
  {
    adxrna_GetTime = getTimeCallback;
  }

  [[maybe_unused]] void adxrna_CommitOutputSyncState(const std::int32_t rnaHandle);

  /**
   * Address: 0x00B15370 (FUN_00B15370, sub_B15370)
   *
   * What it does:
   * Dispatches one aligned silent transfer chunk from ADXRNA scratch lanes and
   * stores returned carry units for later cursor reconciliation.
   */
  [[maybe_unused]] std::int32_t mwlRnaDispatchScratchTransfer(MwlRnaRuntimeView* const runtime)
  {
    const std::int32_t bitsPerSample = runtime->bitsPerSample;
    const std::int32_t transferCapacityBytes = runtime->transferCapacityBytes;
    std::int32_t dispatchedCarryUnits = 0;
    const std::int32_t unitStride = 8 * (32 / bitsPerSample);
    const std::int32_t capacityRemaining = transferCapacityBytes - runtime->transferFreezePosition;
    std::int32_t transferUnits = unitStride
      * ((transferCapacityBytes - runtime->transferAccumulatedUnits - runtime->transferConsumedBytes) / unitStride);
    if (transferUnits >= capacityRemaining) {
      transferUnits = capacityRemaining;
    }

    const std::int32_t maxSectorTransferUnits = 8 * (2048 / bitsPerSample);
    if (transferUnits >= maxSectorTransferUnits) {
      transferUnits = maxSectorTransferUnits;
    }

    transferUnits = unitStride * (transferUnits / unitStride);
    if (transferUnits <= 0) {
      return 0;
    }

    std::uint8_t* scratchBase = gAdxrnaScratchStateA.data();
    if (bitsPerSample != 4) {
      scratchBase = gAdxrnaScratchStateB.data();
    }

    const std::uintptr_t scratchAddressAligned
      = (reinterpret_cast<std::uintptr_t>(scratchBase + 32u)) & static_cast<std::uintptr_t>(~0x1Fu);
    const std::int32_t scratchWordAddress = static_cast<std::int32_t>(scratchAddressAligned);

    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    if (channelCount > 0) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        dispatchedCarryUnits = mwlRnaDispatchTransferChunk(
          runtime,
          channelIndex,
          runtime->transferFreezePosition,
          scratchWordAddress,
          transferUnits
        );
      }
    }

    runtime->transferCarryUnits = dispatchedCarryUnits;
    return dispatchedCarryUnits;
  }

  /**
   * Address: 0x00B15430 (FUN_00B15430, sub_B15430)
   *
   * What it does:
   * Reconciles desired play/volume/sample-rate control lanes with output runtime
   * dispatch state and updates applied-value mirrors.
   */
  [[maybe_unused]] std::int32_t adxrna_SyncOutputControlLanes(AdxrnaTransportRuntimeView* const runtime)
  {
    auto* const playSwitchRuntime = reinterpret_cast<AdxrnaPlaySwitchRuntimeView*>(runtime);
    auto* const metricsRuntime = reinterpret_cast<AdxrnaLegacyMetricsRuntimeView*>(runtime);
    const std::int32_t requestedPlaySwitch = playSwitchRuntime->playSwitch;
    const std::int32_t appliedPlaySwitch = playSwitchRuntime->appliedPlaySwitch;

    if (requestedPlaySwitch == appliedPlaySwitch) {
      if (appliedPlaySwitch == 1 && playSwitchRuntime->stopTransitionPending == 1) {
        runtime->outputRuntime->dispatchTable->pausePlayback(runtime->outputRuntime);
        if (gAdxrnaPauseAllState != 1) {
          runtime->outputRuntime->dispatchTable->startPlayback(runtime->outputRuntime);
        }
        playSwitchRuntime->stopTransitionPending = 0;
      }
    } else {
      if (requestedPlaySwitch == 1) {
        if (gAdxrnaPauseAllState != 1) {
          runtime->outputRuntime->dispatchTable->startPlayback(runtime->outputRuntime);
          playSwitchRuntime->appliedPlaySwitch = playSwitchRuntime->playSwitch;
          goto sync_metrics_lanes;
        }
      } else {
        runtime->outputRuntime->dispatchTable->pausePlayback(runtime->outputRuntime);
        playSwitchRuntime->stopTransitionPending = 0;
      }
      playSwitchRuntime->appliedPlaySwitch = playSwitchRuntime->playSwitch;
    }

  sync_metrics_lanes:
    if (metricsRuntime->streamInfoWordA0 != metricsRuntime->appliedOutputVolume) {
      runtime->outputRuntime->dispatchTable->setOutputVolume(runtime->outputRuntime, metricsRuntime->streamInfoWordA0);
      metricsRuntime->appliedOutputVolume = metricsRuntime->streamInfoWordA0;
    }

    std::int32_t result = metricsRuntime->appliedSampleRate;
    if (metricsRuntime->calculatedSampleRate != metricsRuntime->appliedSampleRate) {
      runtime->outputRuntime->dispatchTable->setLaneWordPair(runtime->outputRuntime, 5, metricsRuntime->calculatedSampleRate, 0);
      result = metricsRuntime->calculatedSampleRate;
      metricsRuntime->appliedSampleRate = result;
    }
    return result;
  }

  /**
   * Address: 0x00B15530 (FUN_00B15530, sub_B15530)
   *
   * What it does:
   * Toggles global ADXRNA pause-all state and applies pause/resume dispatch
   * across active RNA runtime lanes.
   */
  [[maybe_unused]] std::int32_t adxrna_SetPauseAllState(const std::int32_t pauseAllEnabled)
  {
    std::int32_t result = gAdxrnaPauseAllState;
    if (pauseAllEnabled == 1) {
      if (gAdxrnaPauseAllState != 1) {
        gAdxrnaPauseAllState = 1;
        for (auto& runtime : gAdxrnaRuntimePool) {
          if (runtime.inUse == 1u) {
            result = runtime.outputRuntime->dispatchTable->pausePlayback(runtime.outputRuntime);
          }
        }
      }
    } else if (gAdxrnaPauseAllState != 0) {
      for (auto& runtime : gAdxrnaRuntimePool) {
        const std::int32_t rnaHandle = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&runtime));
        result = rnaHandle;
        if (runtime.inUse == 1u) {
          result = static_cast<std::int32_t>((runtime.stateFlags >> 1) & 1u);
          if (result == 1) {
            result = runtime.outputRuntime->dispatchTable->startPlayback(runtime.outputRuntime);
          }
        }
      }
      gAdxrnaPauseAllState = 0;
    }
    return result;
  }

  /**
   * Address: 0x00B155C0 (FUN_00B155C0, sub_B155C0)
   *
   * What it does:
   * Returns global ADXRNA pause-all state lane.
   */
  [[maybe_unused]] std::int32_t adxrna_GetPauseAllState()
  {
    return gAdxrnaPauseAllState;
  }

  /**
   * Address: 0x00B155D0 (FUN_00B155D0, sub_B155D0)
   *
   * What it does:
   * Latches output-sync request state and runs one immediate sync pass for the
   * target RNA handle.
   */
  [[maybe_unused]] void adxrna_RequestOutputSyncPass(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    CRICRS_Enter();
    if (runtime->outputSyncPending == 0u) {
      const std::int32_t playEnabled = static_cast<std::int32_t>((runtime->stateFlags >> 1) & 1u);
      const std::int32_t transferEnabled = static_cast<std::int32_t>(runtime->stateFlags & 1u);
      const std::uint8_t pendingTransferAck = runtime->pendingTransferAck;
      runtime->outputSyncStateWord = transferEnabled | (2 * playEnabled);
      runtime->outputSyncPending = 1u;
      if (pendingTransferAck == 1u) {
        runtime->transitionGuardFlag = 1;
        CRICRS_Leave();
        for (std::int32_t pollIndex = 0; pollIndex < kAdxrnaTransferDrainPollLimit; ++pollIndex) {
          if (runtime->transferStopPending == 0) {
            break;
          }

          std::int32_t channel0Stopped = 1;
          std::int32_t channel1Stopped = 1;
          const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
          for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
            if (runtime->outputRuntime->dispatchTable->isChannelStopped(runtime->outputRuntime, channelIndex) != 1) {
              if (channelIndex == 0) {
                channel0Stopped = 0;
              } else {
                channel1Stopped = 0;
              }
            }
          }

          if (channel0Stopped != 0 && channel1Stopped != 0) {
            runtime->transferStopPending = 0;
            break;
          }
        }
        CRICRS_Enter();
        runtime->transitionGuardFlag = 0;
      }
      adxrna_CommitOutputSyncState(rnaHandle);
    }
    CRICRS_Leave();
  }

  /**
   * Address: 0x00B15670 (FUN_00B15670, sub_B15670)
   *
   * What it does:
   * Completes one pending output-sync pass and restores play-switch lane when
   * latched sync state requires active playback.
   */
  [[maybe_unused]] void adxrna_CompleteOutputSyncPass(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    CRICRS_Enter();
    if (runtime->outputSyncPending == 1u) {
      if (runtime->outputSyncStateWord >= 2) {
        auto* const playSwitchRuntime = AsAdxrnaPlaySwitchRuntimeView(rnaHandle);
        playSwitchRuntime->playSwitch = 1;
        if (((playSwitchRuntime->stateFlags >> 1) & 1u) != 1u) {
          playSwitchRuntime->stateFlags = static_cast<std::uint8_t>(playSwitchRuntime->stateFlags | 0x02u);
        }
      }
      runtime->outputSyncPending = 0u;
    }
    CRICRS_Leave();
  }

  /**
   * Address: 0x00B156D0 (FUN_00B156D0, sub_B156D0)
   *
   * What it does:
   * Returns ADXRNA output-sync-pending flag.
   */
  [[maybe_unused]] std::int32_t adxrna_IsOutputSyncPending(const std::int32_t rnaHandle)
  {
    if (rnaHandle != 0) {
      return static_cast<std::int32_t>(AsAdxrnaTransportRuntimeView(rnaHandle)->outputSyncPending);
    }

    CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
    return 0;
  }

  /**
   * Address: 0x00B156F0 (FUN_00B156F0, sub_B156F0)
   *
   * What it does:
   * Commits one pending transfer/output sync pass, reconciling transport cursor
   * lanes from output-consumed unit counts.
   */
  [[maybe_unused]] void adxrna_CommitOutputSyncState(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    CRICRS_Enter();
    if (runtime->pendingTransferAck == 1u) {
      if ((runtime->stateFlags & 0x01u) != 0u) {
        const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
        for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
          void* const sjHandle = (channelIndex == 0) ? runtime->channelJoinHandle0 : runtime->channelJoinHandle1;
          if (sjHandle == nullptr) {
            CRIERR_CallErr(kMwlRnaAddWrPosNullSjMessage);
          }
        }

        const std::int32_t pendingUnits = runtime->pendingTransferUnits;
        const std::int32_t wrappedWritePosition = (runtime->transferWritePosition + pendingUnits) % runtime->transferRingSize;
        runtime->pendingTransferUnits = 0;
        runtime->queuedDataUnits += pendingUnits;
        runtime->transferWritePosition = wrappedWritePosition;
        runtime->decodedDataUnits += pendingUnits;
      } else {
        const std::int32_t transferCarryUnits = runtime->transferCarryUnits;
        const std::int32_t combinedWritePosition = transferCarryUnits + runtime->transferFreezePosition;
        runtime->transferCarryUnits = 0;
        runtime->transferFreezePosition = combinedWritePosition % runtime->transferRingSize;
        runtime->transferAccumulatedUnits += transferCarryUnits;
      }
      runtime->pendingTransferAck = 0;
    }

    const std::int32_t transferReadCursor = runtime->transferReadPosition;
    if (transferReadCursor != 0 && runtime->queuedDataUnits > 0) {
      std::int32_t consumedUnits = 0;
      const std::int32_t dispatchedUnits =
        runtime->outputRuntime->dispatchTable->consumeTransferUnits(runtime->outputRuntime, transferReadCursor, &consumedUnits);
      if (runtime->outputSyncStateWord == 2) {
        runtime->transferFreezePosition
          = (runtime->transferRingSize + runtime->transferFreezePosition - consumedUnits) % runtime->transferRingSize;
      }

      runtime->transferWritePosition
        = (runtime->transferRingSize + runtime->transferWritePosition - consumedUnits) % runtime->transferRingSize;
      runtime->transferReadPosition += (dispatchedUnits - consumedUnits);
      runtime->queuedDataUnits -= dispatchedUnits;
    }

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B15910 (FUN_00B15910, mwRnaSetNumChan)
   *
   * What it does:
   * Validates requested RNA channel count against runtime max-channel lane,
   * stores active count, and forwards the update to the output runtime bridge.
   */
  void __cdecl mwRnaSetNumChan(AdxrnaRuntimeView* const runtime, const std::int32_t channelCount)
  {
    if (runtime == nullptr) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    if (channelCount > static_cast<std::int32_t>(runtime->maxChannelCount)) {
      CRIERR_CallErr(kMwRnaSetNumChanIllegalChannelMessage);
      return;
    }

    runtime->channelCount = static_cast<std::uint8_t>(channelCount);
    runtime->outputRuntime->dispatchTable->setChannelCount(runtime->outputRuntime, static_cast<std::int8_t>(channelCount));
  }

  [[nodiscard]] std::int32_t M2aGetCurrentSlotIndex(const M2aDecoderContext* context)
  {
    return context->activeElementIndex + (context->activeWindowGroupIndex << 5);
  }

  [[nodiscard]] std::int32_t* M2aContextWords(M2aDecoderContext* context)
  {
    return reinterpret_cast<std::int32_t*>(context);
  }

  [[nodiscard]] const std::int32_t* M2aContextWords(const M2aDecoderContext* context)
  {
    return reinterpret_cast<const std::int32_t*>(context);
  }

  template <typename T>
  [[nodiscard]] T* M2aWordToPtr(const std::int32_t addressWord)
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(addressWord)));
  }

  [[nodiscard]] std::int32_t M2aPtrToWord(const void* pointer)
  {
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(pointer));
  }

  [[nodiscard]] void* M2aAllocFromHeap(const std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    int allocatedPointer = 0;
    if (heapManagerHandle != 0 && HEAPMNG_Allocate(heapManagerHandle, byteCount, &allocatedPointer) >= 0) {
      return M2aWordToPtr<void>(allocatedPointer);
    }
    return nullptr;
  }

  [[nodiscard]] std::int32_t M2aGetHeapManagerHandle(const M2aDecoderContext* context)
  {
    return M2aContextWords(context)[kM2aContextHeapManagerIndex];
  }

  void M2aInitializeIcsWindowPointers(std::int32_t* const icsInfo)
  {
    auto* sectionCodebookLane = reinterpret_cast<std::uint8_t*>(icsInfo + 2);
    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      icsInfo[114 + windowIndex] = M2aPtrToWord(sectionCodebookLane);
      sectionCodebookLane += 56;
    }
  }

  void M2aInitializeDecodeStateWindowPointers(std::int32_t* const decodeState)
  {
    auto* sectionCodebookLane = reinterpret_cast<std::uint8_t*>(decodeState + 114);
    auto* spectralBase = reinterpret_cast<std::uint8_t*>(decodeState + 1568);

    for (std::int32_t windowIndex = 0; windowIndex < kM2aShortWindowCount; ++windowIndex) {
      decodeState[234 + windowIndex] = M2aPtrToWord(sectionCodebookLane);
      decodeState[226 + windowIndex] = M2aPtrToWord(sectionCodebookLane - 448);
      decodeState[3616 + windowIndex] = M2aPtrToWord(spectralBase - 4096);
      decodeState[3624 + windowIndex] = M2aPtrToWord(spectralBase);
      decodeState[3632 + windowIndex] = M2aPtrToWord(spectralBase + 4096);

      sectionCodebookLane += 56;
      spectralBase += 512;
    }
  }

  [[nodiscard]] std::int32_t* M2aGetIcsInfoLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextIcsTableBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetPrimaryStateLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPrimaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetSecondaryStateLane(const M2aDecoderContext* context)
  {
    const auto slotIndex = static_cast<std::size_t>(M2aGetCurrentSlotIndex(context));
    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextSecondaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetPrimaryStateBySlot(const M2aDecoderContext* context, const std::int32_t slotIndex)
  {
    if (slotIndex < 0 || slotIndex >= 16) {
      return nullptr;
    }

    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextPrimaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] std::int32_t* M2aGetSecondaryStateBySlot(const M2aDecoderContext* context, const std::int32_t slotIndex)
  {
    if (slotIndex < 0 || slotIndex >= 16) {
      return nullptr;
    }

    return M2aWordToPtr<std::int32_t>(M2aContextWords(context)[kM2aContextSecondaryStateBaseIndex + slotIndex]);
  }

  [[nodiscard]] float* M2aGetDecodeStatePcmWindow(std::int32_t* const decodeState)
  {
    if (decodeState == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(decodeState) + kM2aDecodeStatePcmWindowOffset);
  }

  [[nodiscard]] const float* M2aGetDecodeStatePcmWindow(const std::int32_t* const decodeState)
  {
    if (decodeState == nullptr) {
      return nullptr;
    }

    return reinterpret_cast<const float*>(reinterpret_cast<const std::uint8_t*>(decodeState) + kM2aDecodeStatePcmWindowOffset);
  }

  [[nodiscard]] bool M2aHasReadyPcmWindow(const std::int32_t* const decodeState)
  {
    return decodeState != nullptr &&
           decodeState[kM2aDecodeStateOutputReadySamplesIndex] >= kM2aPcmWindowSampleCount;
  }

  void M2aAccumulateScaledPcmWindow(float* destination, const float* source, const float scale)
  {
    for (std::int32_t sampleIndex = 0; sampleIndex < kM2aPcmWindowSampleCount; ++sampleIndex) {
      destination[sampleIndex] += source[sampleIndex] * scale;
    }
  }

  void M2aAccumulatePairedPcmWindow(float* destination, const float* leftSource, const float* rightSource, const float scale)
  {
    for (std::int32_t sampleIndex = 0; sampleIndex < kM2aPcmWindowSampleCount; ++sampleIndex) {
      destination[sampleIndex] += (leftSource[sampleIndex] + rightSource[sampleIndex]) * scale;
    }
  }

  [[nodiscard]] std::int32_t M2aSumScalefactorBandWidths(
    const std::int32_t* bandWidths,
    const std::int32_t startBand,
    const std::int32_t endBand
  )
  {
    std::int32_t totalLines = 0;
    for (std::int32_t band = startBand; band < endBand; ++band) {
      totalLines += bandWidths[band];
    }
    return totalLines;
  }

  void M2aBuildTnsFilterCoefficients(float* coefficients, const float* decodedCoefficients, const std::int32_t order)
  {
    float scratch[kM2aTnsCoefficientLaneCount]{};
    coefficients[0] = 1.0f;

    for (std::int32_t coefficientIndex = 1; coefficientIndex <= order; ++coefficientIndex) {
      scratch[0] = coefficients[0];
      if (coefficientIndex > 1) {
        const auto reflectionCoefficient = decodedCoefficients[coefficientIndex - 1];
        for (std::int32_t lane = 1; lane < coefficientIndex; ++lane) {
          scratch[lane] =
            reflectionCoefficient * coefficients[coefficientIndex - lane] + coefficients[lane];
        }
      }

      scratch[coefficientIndex] = decodedCoefficients[coefficientIndex - 1];
      std::memcpy(coefficients, scratch, static_cast<std::size_t>(coefficientIndex + 1) * sizeof(float));
    }
  }

  void M2aApplyTnsFilter(
    float* spectralCoefficients,
    const std::int32_t lineCount,
    const float* filterCoefficients,
    const std::int32_t filterOrder,
    const bool reverseDirection
  )
  {
    float filterHistory[kM2aTnsCoefficientLaneCount]{};
    m2adec_clear(filterHistory, sizeof(filterHistory));

    if (!reverseDirection) {
      for (std::int32_t line = 0; line < lineCount; ++line) {
        double filteredValue = spectralCoefficients[line];
        for (std::int32_t lane = 0; lane < filterOrder; ++lane) {
          filteredValue -= static_cast<double>(filterHistory[lane]) * static_cast<double>(filterCoefficients[lane]);
        }

        for (std::int32_t lane = filterOrder - 1; lane > 0; --lane) {
          filterHistory[lane] = filterHistory[lane - 1];
        }

        filterHistory[0] = static_cast<float>(filteredValue);
        spectralCoefficients[line] = static_cast<float>(filteredValue);
      }
      return;
    }

    for (std::int32_t line = lineCount - 1; line > 0; --line) {
      double filteredValue = spectralCoefficients[line];
      for (std::int32_t lane = 0; lane < filterOrder; ++lane) {
        filteredValue -= static_cast<double>(filterHistory[lane]) * static_cast<double>(filterCoefficients[lane]);
      }

      for (std::int32_t lane = filterOrder - 1; lane > 0; --lane) {
        filterHistory[lane] = filterHistory[lane - 1];
      }

      filterHistory[0] = static_cast<float>(filteredValue);
      spectralCoefficients[line] = static_cast<float>(filteredValue);
    }
  }

  constexpr std::size_t kXeficObjectCount = 16;
  constexpr std::size_t kAdxrnaTimingPoolCount = 32;
  constexpr double kMicrosToSamples = 0.0441;
  constexpr double kMicrosToNegativeSamples = -0.0441;
  constexpr std::uint32_t kXeficWorkerSleepMilliseconds = 10;

  // Banner string lane mirrored by adxrna_Init startup reads.
  constexpr const char* kRnaVersionBanner = "\nRNADMY Ver.3.06 Build:Feb 28 2005 21:53:03\n";
  constexpr const char* kXeficEventNameFormat = "%s%s";
  constexpr const char* kXeficEventOpenedFormat = "%s is opened.\n";
  constexpr const char* kXeficEventClosedFormat = "%s is closed.\n";
  constexpr const char* kInitializeCriticalSectionFailedMessage = "E2005020901 : InitializeCriticalSection function has failed.";
  constexpr const char* kDeleteCriticalSectionFailedMessage = "E2005020902 : DeleteCriticalSection function has failed.";
  constexpr const char* kEnterCriticalSectionFailedMessage = "E2005020903 : EnterCriticalSection function has failed.";
  constexpr const char* kLeaveCriticalSectionFailedMessage = "E2005020904 : LeaveCriticalSection function has failed.";
  constexpr const char* kM2asjdInitializeCriticalSectionFailedMessage = "InitializeCriticalSection function has failed.";
  constexpr const char* kM2asjdDeleteCriticalSectionFailedMessage = "DeleteCriticalSection function has failed.";
  constexpr const char* kM2asjdEnterCriticalSectionFailedMessage = "EnterCriticalSection function has failed.";
  constexpr const char* kM2asjdLeaveCriticalSectionFailedMessage = "LeaveCriticalSection function has failed.";
  constexpr const char* kM2asjdCreateNullPointerMessage = "E2004012901 : Null pointer is specified.";
  constexpr const char* kM2asjdDestroyNullPointerMessage = "E2004012903 : Null pointer is specified.";
  constexpr const char* kM2asjdResetNullPointerMessage = "E2004012904 : Null pointer is specified.";
  constexpr const char* kM2asjdNullDecoderHandleMessage = "E2004012905 : Null pointer is specified.";
  constexpr const char* kM2asjdStartNullPointerMessage = "E2004012907 : Null pointer is specified.";
  constexpr const char* kM2asjdStopNullPointerMessage = "E2004012908 : Null pointer is specified.";
  constexpr const char* kM2asjdGetStatusNullPointerMessage = "E2004012909 : Null pointer is specified.";
  constexpr const char* kM2asjdGetNumChannelsNullPointerMessage = "E2004012910 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetChannelConfigNullPointerMessage = "E2004012911 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetFrequencyNullPointerMessage = "E2004012912 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetNumBitsNullPointerMessage = "E2004012913 : NULL pointer is specified.";
  constexpr const char* kM2asjdGetNumSmplsDcdNullPointerMessage = "E02092701 : Null pointer is specified.";
  constexpr const char* kM2asjdGetNumBytesDcdNullPointerMessage = "E02092702 : Null pointer is specified.";
  constexpr const char* kM2asjdIllegalParameterMessage = "Illegal parameter is specified.";
  constexpr const char* kM2asjdGenericNullPointerMessage = "Null pointer is specified.";
  constexpr const char* kMpasjdWorkSizeTooSmallMessage = "Work size is too small.";
  constexpr std::int32_t kMpasjdMinimumWorkBytes = 0xC080;
  constexpr std::int32_t kMpasjdWorkBaseOffsetBytes = 0x80;
  constexpr std::int32_t kMpasjdReservedWorkBytes = 0x2080;
  constexpr std::int32_t kMpasjdStateStopped = 0;
  constexpr std::int32_t kMpasjdStatePrimed = 1;
  constexpr std::int32_t kMpasjdStateRunning = 2;
  constexpr std::int32_t kMpasjdStateFlushed = 3;
  constexpr std::int32_t kMpasjdSamplesPerBlock = 96;
  constexpr std::int32_t kMpasjdBlocksPerFrame = 12;
  constexpr std::array<std::int32_t, 4> kMpegAudioSampleRateByHeaderIndex{44100, 48000, 32000, 0};
  constexpr const char* kM2asjdAllocateDecoderMemoryMessage = "E2004012920 : Can not allocate memory for decoder.";
  constexpr const char* kM2asjdResumeAdifDecodeMessage = "E2004012921 : Can not resume decoding in ADIF format.";
  constexpr const char* kM2asjdUnknownDecoderErrorMessage = "E2004012922 : Unknown error occurred in decoder.";
  constexpr std::int32_t kM2asjdBitsPerSample = 16;
  constexpr std::int32_t kM2asjdStatePrimed = 1;
  constexpr std::int32_t kM2asjdStateRunning = 2;
  constexpr std::int32_t kM2asjdStateFlushed = 3;
  constexpr std::int32_t kM2asjdStateError = 4;
  constexpr std::int32_t kM2asjdDecoderStatusFlushed = 2;
  constexpr std::int32_t kM2asjdDecoderStatusError = 3;
  constexpr std::int32_t kM2asjdDecoderErrorOutOfMemory = 1;
  constexpr std::int32_t kM2asjdDecoderErrorAdifResume = 2;
  constexpr std::int32_t kM2asjdOutputModeStereo = 1;
  constexpr std::int32_t kM2asjdOutputModeSurround = 2;
  constexpr std::int32_t kM2asjdOutputModeAdx = 0xFF;
  constexpr std::int32_t kM2asjdLaneSource = 1;
  constexpr std::int32_t kM2asjdLaneOutput = 0;
  constexpr std::int32_t kM2asjdMinimumProcessBytes = 0x800;
  constexpr std::int32_t kM2asjdProcessWindowBytes = 0x2000;
  constexpr std::int32_t kM2asjdSetIoMaxOutputStreams = 6;
  constexpr std::int32_t kM2asjdGetIoReportedOutputStreams = 2;
  constexpr std::int32_t kM2asjdTermSupplyEnabled = 1;
  constexpr const char* kCreateThreadFailedMessage = "E2005021001 : CreateThread function has failed.";
  constexpr const char* kResumeThreadFailedMessage = "E2005021002 : ResumeThread function has failed.";
  constexpr std::size_t kAdxerrCopyLimit = 0xFFu;
  constexpr const char* kAdxerrSeparator = " ";
  constexpr const char* kXeciFileNameNullMessage = "E0092901:fname is null.(wxCiGetFileSize)";
  constexpr const char* kXeciOpenNullFileNameMessage = "E0092908:fname is null.(wxCiOpen)";
  constexpr const char* kXeciOpenInvalidRwMessage = "E0092909:rw is illigal.(wxCiOpen)";
  constexpr const char* kXeciOpenNoHandleMessage = "E0092910:not enough handle resource.(wxCiOpen)";
  constexpr const char* kXeciNullHandleMessage = "E0092912:handl is null.";
  constexpr const char* kXeciReqReadNegativeCountMessage = "E0092913:nsct < 0.(wxCiReqRd)";
  constexpr const char* kXeciReqReadNullBufferMessage = "E0092914:buf is null.(wxCiReqRd)";
  constexpr const char* kXeciReqReadIllegalSizeMessage = "E0109151:illegal read size.";
  constexpr const char* kXeciReqReadIllegalSeekMessage = "E0109152:illegal seek position.";
  constexpr const char* kXeciReqReadIllegalBufferAlignmentMessage = "E0109153:illegal buffer alignment.";
  constexpr const char* kXeciReadCompletionErrorMessage = "E0109251:The reading error occurred.";
  constexpr const char* kXeciGetSctLenNullHandleMessage = "E0040301:handl is null.";
  constexpr const char* kMfciSetSctLenNullHandleMessage = "E0040302:handl is null.";
  constexpr const char* kMfciOpenEntryInvalidEntryCountMessage = "E1041001:invalid entry number.(mfCiOpenEntry)";
  constexpr const char* kMfciOpenEntryInvalidRwModeMessage = "E1041002:rw is illigal.(mfCiOpenEntry)";
  constexpr const char* kMfciOpenEntryNoHandleResourceMessage = "E1041002:not enough handle resource.(mfCiOpenEntry)";
  constexpr const char* kMfciSeekNullHandleMessage = "E01100305:handl is null.";
  constexpr const char* kMfciTellNullHandleMessage = "E01100306:handl is null.";
  constexpr const char* kMfciGetAdrSizeInvalidLengthFormat = "E01100308:length of '%s' is not 17 bytes.(mfci_get_adr_size)";
  constexpr const char* kMfciGetAdrSizeInvalidFormat = "E01100309:illegal file name format '%s'(mfci_get_adr_size)";
  constexpr const char* kXeciGetFileSizeOpenErrorFormat = "E0040201:can not open '%s'.(wxCiGetFileSize)";
  constexpr const char* kXeciOpenFileFailedFormat = "E0092911:can not open '%s'.(err:%d)";
  constexpr const char* kXeciReadZeroByteSyncMessage = "E02052101:The reading start position is invalid for synchronous read.";
  constexpr const char* kXeciReadInvalidStartMessage = "E02052001:The reading start position is invalid.";
  constexpr const char* kXeciReadInvalidHandleMessage = "E02040401:The reading error occurred.";
  constexpr const char* kXeciReadFaultMessage = "E02040901:The reading error occurred.";
  constexpr const char* kXeciReadQueueOverflowMessage = "E02050801:Too many I/O requests.";
  constexpr const char* kXeciReadLastErrorFormat = "E02052002:The reading error occurred. (%d)\n";
  constexpr const char* kXeciCloseWaitTimeoutMessage = "E02082801:Timeout. (Waiting for close handle)";
  constexpr const char* kXeciForceUnlockedMessage = "E02082301 : force unlocked.\n";
  constexpr const char* kXeciReadAbortedMessage = "E02052004:The file reading was aborted.\n";
  constexpr const char* kXeciReadReachedEofMessage = "E02052003:Reached the end of the file during asynchronous operation.\n";
  constexpr const char* kXeciReadErrorFormat = "E02052005:The reading error occurred. (%d)\n";
  constexpr const char* kXeficDisableFileMissingCacheEntryFormat = "E0111091:'%s' is not in cache (wxFicDisableFile).";
  constexpr const char* kXeficEnableFileMissingCacheEntryFormat = "E0111092:'%s' is not in cache (wxFicEnableFile).";
  constexpr const char* kXeficEnableFileOpenErrorFormat = "E0109191:can not open '%s'(wxFicEnableFile).";
  constexpr const char* kXeficInitialWorkBufferShortMessage = "E0109071:work is in short.";
  constexpr const char* kXeficGetHeapHandleFailedMessage = "E0109072:can not get heap handle.";
  constexpr const char* kXeficAllocateWorkBufferFailedMessage = "E0109073:can not allocate memory.";
  constexpr const char* kXeficBuildQueueOpenErrorFormat = "E0109075:can not open '%s'.(wxfic_cache_file)";
  constexpr const char* kXeficWorkBufferShortMessage = "E0109076:work is in short.";
  constexpr const char* kXeciUnlockBeforeLockMessage = "E2003062702 : Unlock was performed before lock.";
  constexpr const char* kXeciWaitTimeoutMessage = "E0109232:Timeout. (Waiting for transmission)";
  constexpr std::int64_t kXeciInvalidFileSizeSentinel = 0x7FFFFFFFFFFFF800LL;
  constexpr std::int32_t kXeciObjectCount = 80;
  constexpr std::int32_t kXeciStateError = 3;
  constexpr std::int32_t kXeciStateTransferring = 2;
  constexpr std::int32_t kXeciTimeoutPollLimit = 25000;
  constexpr std::int64_t kXeciWaitOneMilliDivisor = 1000;
  constexpr const char* kAdxtNullWorkPointerMessage = "E03090101 : NULL pointer is specified.";
  constexpr const char* kAdxtShortWorkBufferMessage = "E03090102 : Work size is too short.";
  constexpr const char* kAdxtShortAlignedWorkBufferMessage = "E03091001 : Work size is too short.";
  constexpr const char* kAdxtDestroyParameterErrorMessage = "E02080805 adxt_Destroy: parameter error";
  constexpr const char* kAdxtStopParameterErrorMessage = "E02080813 adxt_Stop: parameter error";
  constexpr const char* kAdxtGetStatParameterErrorMessage = "E02080814 adxt_GetStat: parameter error";
  constexpr const char* kAdxtGetNumSmplParameterErrorMessage = "E02080817 adxt_GetNumSmpl: parameter error";
  constexpr const char* kAdxtGetSfreqParameterErrorMessage = "E02080819 adxt_GetSfreq: parameter error";
  constexpr const char* kAdxtGetNumChanParameterErrorMessage = "E02080820 adxt_GetNumChan: parameter error";
  constexpr const char* kAdxtGetFmtBpsParameterErrorMessage = "E02080821 adxt_GetFmtBps: parameter error";
  constexpr const char* kAdxtGetHdrLenParameterErrorMessage = "E02080822 adxt_GetHdrLen: parameter error";
  constexpr const char* kAdxtSetOutPanNullRuntimeMessage = "E02080825 adxt_SetOutPan: parameter error";
  constexpr const char* kAdxtSetOutPanLaneRangeMessage = "E8101208 adxt_SetOutPan: parameter error";
  constexpr const char* kAdxsjdDecodePrepAlignmentErrorPrefix = "E04102501 adxsjd_decode_prep: ";
  constexpr const char* kAdxsjdDecodePrepAlignmentErrorMessage = "The data alignment is illegal.";
  constexpr const char* kAdxsjdDecodePrepHeaderErrorPrefix = "E03010901 ADXB_DecodeHeader: ";
  constexpr const char* kAdxsjdDecodePrepHeaderErrorMessage = "Can not decode this file format.";
  constexpr const char* kAdxtDolbySetParamsNullRuntimeMessage = "E2003091605 : NULL pointer is specified.";
  constexpr const char* kAdxtDolbySetParamsInvalidRuntimeMessage =
    "E2003091606 : ADXT handle must be created for 3D sound.";
  constexpr const char* kAdxtNullMatrixStateMessage = "E03090306 : NULL pointer is specified.";
  constexpr const char* kAdxtIllegalMatrixParameterMessage = "E03090307 : Illegal parameter is specified.";
  constexpr const char* kAdxtNullRateStateMessage = "E03091601 : NULL pointer is specified.";
  constexpr const char* kAdxtIllegalRateParameterMessage = "E03091602 : Illegal parameter is specified.";
  constexpr const char* kMparbdNullPointerMessage = "NULL pointer is specified.";
  constexpr const char* kMparbdCreateFunctionName = "MPARBD_Create";
  constexpr const char* kMparbdDestroyFunctionName = "MPARBD_Destroy";
  constexpr const char* kMparbdResetFunctionName = "MPARBD_Reset";
  constexpr const char* kMparbdExecHandleFunctionName = "MPARBD_ExecHndl";
  constexpr const char* kMparbdGetDecodeStatusFunctionName = "MPARBD_GetDecStat";
  constexpr const char* kMparbfGetEndStatusFunctionName = "MPARBF_GetEndStat";
  constexpr const char* kMparbdDecodeSamplesProcFunctionName = "mparbd_decsmpl_proc";
  constexpr const char* kMparbdGetNumSamplesDecodedFunctionName = "MPARBD_GetNumSmplDcd";
  constexpr const char* kMparbdGetNumBytesDecodedFunctionName = "MPARBD_GetNumByteDcd";
  constexpr const char* kMparbdGetSampleRateFunctionName = "MPARBD_GetSfreq";
  constexpr const char* kMparbdGetNumChannelFunctionName = "MPARBD_GetNumChannel";
  constexpr const char* kMparbdGetNumBitFunctionName = "MPARBD_GetNumBit";
  constexpr const char* kMpardTermSupplyFunctionName = "MPARD_TermSupply";
  constexpr std::int32_t kMparbdCreateNullPointerLine = 182;
  constexpr std::int32_t kMparbdDestroyNullPointerLine = 253;
  constexpr std::int32_t kMparbdResetNullPointerLine = 308;
  constexpr std::int32_t kMparbdExecHandleNullPointerLine = 389;
  constexpr std::int32_t kMparbdGetDecodeStatusNullPointerLine = 747;
  constexpr std::int32_t kMparbfGetEndStatusNullPointerLine = 771;
  constexpr std::int32_t kMparbfSetEndStatusNullPointerLine = 794;
  constexpr std::int32_t kMparbdGetNumSamplesDecodedNullPointerLine = 816;
  constexpr std::int32_t kMparbdGetNumBytesDecodedNullPointerLine = 840;
  constexpr std::int32_t kMparbdGetSampleRateNullPointerLine = 863;
  constexpr std::int32_t kMparbdGetNumChannelNullPointerLine = 894;
  constexpr std::int32_t kMparbdGetNumBitNullPointerLine = 925;
  constexpr std::int32_t kMpardTermSupplyNullPointerLine = 951;
  constexpr std::int32_t kMparbdDecodeSamplesOverrunLine = 697;
  constexpr const char* kMparbdNullPointerSentenceCaseMessage = "Null pointer is specified.";
  constexpr const char* kMparbdDecodeSamplesOverrunMessage =
    "The terminus of a buffer was exceeded while decoding frame sample data.";
  constexpr std::size_t kMparbdSyncStateBaseIndex = 436;
  constexpr std::size_t kMparbdSyncStateCount = 15;
  constexpr std::size_t kMparbdHeaderScratchBaseIndex = 3;
  constexpr std::size_t kMparbdHeaderScratchBytes = 0x6C4;
  constexpr std::size_t kMparbdBitAllocBaseIndex = 451;
  constexpr std::size_t kMparbdBitAllocBytes = 0x100;
  constexpr std::size_t kMparbdScaleFactorSelectBaseIndex = 515;
  constexpr std::size_t kMparbdScaleFactorSelectBytes = 0x100;
  constexpr std::size_t kMparbdScaleFactorBaseIndex = 579;
  constexpr std::size_t kMparbdScaleFactorBytes = 0x300;
  constexpr std::size_t kMparbdDecodeTableDirectBaseIndex = 771;
  constexpr std::size_t kMparbdDecodeTableDirectBytes = 0x80;
  constexpr std::size_t kMparbdDecodeTableGroupedBitsBaseIndex = 803;
  constexpr std::size_t kMparbdDecodeTableGroupedBitsBytes = 0x80;
  constexpr std::size_t kMparbdDecodeTableGroupedBaseIndex = 835;
  constexpr std::size_t kMparbdDecodeTableGroupedBytes = 0x80;
  constexpr std::size_t kMparbdSampleBaseIndex = 867;
  constexpr std::size_t kMparbdSampleBytes = 0x300;
  constexpr std::size_t kMparbdDequantizedSampleBaseIndex = 1059;
  constexpr std::size_t kMparbdDequantizedSampleBytes = 0x300;
  constexpr std::size_t kMparbdSynthesisHistoryBaseIndex = 3301;
  constexpr std::size_t kMparbdSynthesisHistoryBytes = 0x180;
  constexpr std::size_t kMparbdSynthesisInputBaseIndex = 1251;
  constexpr std::size_t kMparbdSynthesisInputBytes = 0x2000;
  constexpr std::size_t kMparbdSynthesisRingCursorIndex0 = 3299;
  constexpr std::size_t kMparbdSynthesisRingCursorIndex1 = 3300;
  constexpr std::size_t kMparbdExecErrorIndex = 3399;
  constexpr std::size_t kMparbdSynthesisScaleCursorIndex = 3400;
  constexpr std::size_t kMparbdPendingFrameIndex = 3401;
  constexpr std::size_t kMparbdPendingReloadFlagIndex = 3403;
  constexpr std::size_t kMparbdPendingReturnBytesIndex = 3404;
  constexpr std::size_t kMparbdRunStateIndex = 0;
  constexpr std::size_t kMparbdSuspendFlagIndex = 1;
  constexpr std::size_t kMparbdLastErrorCodeIndex = 2;
  constexpr std::size_t kMparbdSampleRateIndex = 442;
  constexpr std::size_t kMparbdChannelCountIndex = 445;
  constexpr std::size_t kMparbdDecodedByteCountIndex = 3399;
  constexpr std::size_t kMparbdDecodedBlockCountIndex = 3400;
  constexpr std::size_t kMparbdDecodedFrameCountIndex = 3401;
  constexpr std::int32_t kMparbdStateStartup = 0;
  constexpr std::int32_t kMparbdStatePrepare = 1;
  constexpr std::int32_t kMparbdStateDecodeHeader = 2;
  constexpr std::int32_t kMparbdStateDecodeSamples = 3;
  constexpr std::int32_t kMparbdStateDecodeEnd = 4;
  constexpr std::int32_t kMparbdStateNeedMoreData = 5;
  constexpr std::int32_t kMparbdStateError = 6;
  constexpr std::int32_t kMparbdErrorMalformedFrame = -21;
  constexpr std::int32_t kMparbdErrorSampleOverrun = -22;
  constexpr std::int32_t kMparbdErrorNoDecodedSamples = -31;
  constexpr std::int32_t kMparbdBitsPerSample = 16;
  constexpr std::uint32_t kMparbdHeaderPrefixBytes = 4;
  constexpr std::uint32_t kMparbdMinimumFramePayloadBytes = 0x90;
  constexpr std::uint32_t kMparbdSamplesPerFrameBlock = 192;
  constexpr std::uint32_t kMparbdDecodeBlocksPerFrame = 12;

  [[nodiscard]] void* const* GetSofDecVirtualDispatchTable();

  [[nodiscard]] std::int16_t GenerateKeyLane(const char* sourceBytes, const std::int32_t sourceLength, std::int16_t seed)
  {
    for (std::int32_t index = 0; index < sourceLength; ++index) {
      const auto symbolIndex = static_cast<std::int32_t>(static_cast<signed char>(sourceBytes[index])) + 128;
      const auto lhs = static_cast<std::int32_t>(seed);
      const auto rhs = static_cast<std::int32_t>(skg_prim_tbl[symbolIndex]);
      std::int32_t tableIndex = (lhs * rhs) % 1024;
      if (tableIndex < 0) {
        tableIndex += 1024;
      }
      seed = skg_prim_tbl[tableIndex];
    }

    return seed;
  }

  [[nodiscard]] std::int32_t ConvertMicrosToSamples(const std::int32_t micros, const double scale)
  {
    return static_cast<std::int32_t>(static_cast<double>(static_cast<std::uint32_t>(micros)) * scale);
  }

  [[nodiscard]] MparbfRuntimeBuffer* AsMparbfRuntimeBuffer(const std::int32_t handleAddress)
  {
    return reinterpret_cast<MparbfRuntimeBuffer*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handleAddress))
    );
  }

  void M2aFreeHeapAllocation(const std::int32_t heapManagerHandle, void* allocation)
  {
    if (allocation != nullptr) {
      HEAPMNG_Free(heapManagerHandle, M2aPtrToWord(allocation));
    }
  }

  [[nodiscard]] moho::AdxrnaTimingState* ResetAdxrnaTimingPoolActiveFlags()
  {
    for (auto& timingState : adxrna_timing_pool) {
      timingState.activeFlag = 0;
    }
    return adxrna_timing_pool + kAdxrnaTimingPoolCount;
  }

  [[nodiscard]] moho::AdxrnaTimingState* AcquireFreeAdxrnaTimingState()
  {
    for (auto& timingState : adxrna_timing_pool) {
      if (timingState.activeFlag == 0) {
        return &timingState;
      }
    }
    return nullptr;
  }

  void XeficDumpQueuedEntriesForObject(XeficObject* object)
  {
    char outputString[520]{};
    const auto queuedEntryCount = xefic_GetQueuedEntryCount(object);
    object->queueCursor = object->queueHead;

    if (queuedEntryCount <= 0) {
      return;
    }

    for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
      XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
      std::sprintf(outputString, kXeficEventNameFormat, object->pathPrefix, queueEntry->relativePath);
      if (queueEntry->fileHandle != nullptr) {
        std::sprintf(outputString, kXeficEventOpenedFormat, outputString);
      } else {
        std::sprintf(outputString, kXeficEventClosedFormat, outputString);
      }
      OutputDebugStringA(outputString);
    }
  }

  [[nodiscard]] bool XeficPathPrefixEqualsIgnoreCase(
    const char* const pathPrefix,
    const char* const rootedFileName,
    const std::int32_t compareLength
  )
  {
    for (std::int32_t prefixIndex = 0; prefixIndex < compareLength; ++prefixIndex) {
      const auto rootedSymbol = static_cast<std::uint8_t>(rootedFileName[prefixIndex]) & 0xDFu;
      const auto prefixSymbol = static_cast<std::uint8_t>(pathPrefix[prefixIndex]) & 0xDFu;
      if (rootedSymbol != prefixSymbol) {
        return false;
      }
    }
    return true;
  }

  [[nodiscard]] XeficQueuedFileEntry* XeficFindQueuedFileEntryUnlockedByRootedPath(const char* const rootedFileName)
  {
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0 || object->state == 1) {
        continue;
      }

      const char* const pathPrefix = object->pathPrefix;
      const auto pathPrefixLength = static_cast<std::int32_t>(std::strlen(pathPrefix));
      const auto rootedPathLength = static_cast<std::int32_t>(std::strlen(rootedFileName));
      if (rootedPathLength < pathPrefixLength) {
        continue;
      }
      if (!XeficPathPrefixEqualsIgnoreCase(pathPrefix, rootedFileName, pathPrefixLength)) {
        continue;
      }

      const auto queuedEntryCount = xefic_GetQueuedEntryCount(object);
      object->queueCursor = object->queueHead;
      if (queuedEntryCount <= 0) {
        continue;
      }

      const char* const relativePath = rootedFileName + pathPrefixLength;
      for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
        XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
        if (_stricmp(relativePath, queueEntry->relativePath) == 0) {
          return queueEntry;
        }
      }
    }

    return nullptr;
  }

  void XeficInvokeCriticalSectionApi(
    void(WINAPI* criticalSectionApi)(LPCRITICAL_SECTION),
    const char* const errorMessage
  )
  {
#if defined(_MSC_VER)
    __try {
      criticalSectionApi(&xefic_lock_obj);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      xeci_error(0, errorMessage);
    }
#else
    criticalSectionApi(&xefic_lock_obj);
#endif
  }

  [[nodiscard]] std::int32_t xefind_SetVisitCallback(const XefindVisitCallback callback, void* const callbackContext)
  {
    return xeci_set_unk1(callback, callbackContext);
  }
}

extern "C"
{
  void xefic_init_lock();
  void xefic_delete_lock();
  void xefic_lock();
  void xefic_unlock();
  void xeci_create_thread();
  BOOL xeci_destroy_thread();
  BOOL xeci_save_thread_prio();
  BOOL xeci_set_thread_prio();
  void xefic_DebugDumpQueueForObjectUnlocked(XeficObject* object);
  void xefic_DebugDumpAllQueuesUnlocked();
  const char* __cdecl xefic_obj_pop_relative_path(XeficObject* object);
  std::int32_t __cdecl wxFicGetCachedFileSizeBytes(const char* fileName);
  HANDLE __cdecl
  wxFicGetCachedHandleAndInfo(const char* fileName, std::int32_t* outFileSizeBytes, std::int32_t* outCacheState);
  HANDLE __cdecl wxFicGetCachedHandle(const char* fileName);

