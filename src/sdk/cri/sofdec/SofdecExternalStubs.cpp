// SPDX: faf engine recovery
//
// SofdecExternalStubs.cpp
//
// Linker stubs for Sofdec/CRI middleware symbols.
//
// IMPORTANT: Contrary to the original "external DLL" framing, all 135 of the
// stubbed functions here EXIST IN THE FA BINARY as statically-linked code.
// Sofdec was shipped as object files (.obj) inside ForgedAlliance.exe, not as
// a redistributable DLL. See `decomp/recovery/disasm/fa_full_2026_03_26/` —
// each stubbed name resolves to a `FUN_XXXXXXXX` address with real
// instructions. Total binary code currently replaced by these stubs:
// ~29,876 bytes / ~10,452 x86 instructions.
//
// These stubs exist solely to let the exe LINK while the underlying Sofdec
// recovery remains in progress. They are no-ops that return 0/nullptr and
// will silently suppress all movie playback (SFD/MPV/ADXT/MWSFCRE). Recovery
// targets:
//
//   - Biggest pending: parse_PES_packet_sub (FUN_00AE0F80, 8,869 bytes),
//     cft_c_Ycc420plnToArgb8888Int1smp (FUN_00B03F10, 3,299 bytes),
//     cft_sse_Ycc420plnToArgb8888Int1smp (FUN_00B059E0, 2,259 bytes).
//   - Blocked-by-struct-layout: MPVCMC_*, MPVUMC_*, SFMPVF_GetNumFrm,
//     SFTIM_InitTcode/Ttu, UTY_MemsetDword, mpvcmc_InitMcOiTa,
//     sfmpvf_IsChkFirst/SetPicUsrBuf — bodies exist in
//     cri/sofdec/SofdecMpvRuntime.cpp but that TU has ~25 failing
//     static_asserts on SfmpvHandleRuntimeView + missing helpers
//     (sfmpv_SkipFrm, sfmpv_ConcatSub). See tmp/sofdec_binary_state.tsv
//     for the full prioritized list.
//
// Data stubs are zero-initialized 4 KB buffers; indexed accesses stay
// in-range but yield zeros.
//
// TREAT EVERY DATA STUB BELOW AS SUSPECT. A sweep of these names against
// the PE section map found 28 of them are real initialized .rdata/.data in
// the shipped image — we are silently substituting zeros for live tables,
// which produces subsystems that initialize cleanly and then behave as if
// their content were empty. Two rounds of that were already fixed:
// mpvvlt_run_level_* (the MPEG-1 run/level VLC tables, so every decoder
// lookup returned nothing) and SFD_tr_vd_mpv / SFD_tr_sd_mps /
// SFD_tr_sd_m2ts (transfer-strategy descriptors that existed BOTH here as
// zeros and as populated objects in SofdecSfdRuntime.cpp, with the create
// path binding the zeros).
//
// To classify one: grep the .asm exports for `offset _NAME`, take the
// 4-byte immediate out of the instruction encoding to get its VA, then
// check it against the PE section table — `rva - sectionVA >= rawSize`
// means genuine BSS (a zero stub is correct), otherwise it is initialized
// and the bytes are at `ptr + (rva - sectionVA)`. Size comes from whatever
// copies or walks the table, the way mpvvlc_SetVlcRunLevel gave the
// run/level dword counts.
//
// Still outstanding are the Dolby/MPEG audio tables (dolby_*, sin_*,
// mpadcd_*, alloc_len_*, book, m2adec_*) — that is movie sound. Only 54 of
// these names resolved to addresses via the `offset _NAME` scan; the other
// 71 are referenced some other way and are unclassified.

#include <cstdint>

// === Function stubs (cdecl no-arg, return 0/null) ===
extern "C" {
  void* ADXM_Finish() { return nullptr; }
  // ADXM_SetupThrd (0x00B07C80): real body in SofdecAdxPlatformRuntime.cpp.
  // This is what creates the three Sofdec worker threads. While it was a
  // stub none of them existed, so nothing ticked the SFD decode server and
  // no movie frame was ever decoded.
  // ADXM_WaitVsync (0x00B06E60) parks the caller until the multimedia-timer
  // tick pulses the vsync event. Returning immediately turned every caller's
  // pacing loop into a busy spin - CMovie::OpenMovie's prepare loop in
  // particular, which then starved the Sofdec server threads it was waiting on.
  // Recovered next to the timer tick in cri/sofdec/SofdecMwPlaybackRuntime.cpp.
  void* ADXPC_SetupSoundDirectSound8() { return nullptr; }
  void* ADXRNA_ExecHndl() { return nullptr; }
  void* ADXT_AttachDolbyProLogicII() { return nullptr; }
  void* ADXT_DetachMPEG2AAC() { return nullptr; }
  // ADXT_Init (0x00B0A390): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. This is the ADX runtime bootstrap
  // and, critically, the registrar for the three ADXT server callbacks. While
  // it was a stub nothing ever registered adxt_exec_fssvr on the FS lane, so
  // adxstm_ExecServer never ran and no ADXSTM slot was ever serviced: movies
  // bound their file, started their stream, and read zero bytes forever.
  void* CRIERR_CallErr() { return nullptr; }
  void* M2TSD_Init() { return nullptr; }
  void* M2T_Create() { return nullptr; }
  // The twelve MPS_* public entry points (MPS_DecHd 0x00AEB560, MPS_Destroy
  // 0x00AEB3C0, MPS_Finish 0x00AEB030, MPS_GetElementaryInfo 0x00AECBC0,
  // MPS_GetLastSysHd 0x00AECB40, MPS_GetPackHd 0x00AECAB0, MPS_GetPketHd
  // 0x00AECB80, MPS_GetSysHd 0x00AECB00, MPS_SetPesFn 0x00AEB530,
  // MPS_SetPesSw 0x00AECC00, MPS_SetPsMapFn 0x00AEB500, MPS_SetSystemFn
  // 0x00AEB4D0) have real bodies in cri/sofdec/SofdecSfdRuntime.cpp.
  //
  // As no-arg stubs they answered every call with "no error, nothing
  // parsed", which hung the engine: sfmps_DecodeSomeUnit loops until a
  // callee errors or consumes zero bytes, and a demuxer that always
  // succeeds without consuming satisfies neither.
  // MPS_Create: real body in SofdecSfdRuntime.cpp (0x00AEB200). This stub made
  // SFMPS_Create fail with SFD ERROR(FF000D08) and took every movie with it.
  // TODO(recovery): MPVCMC_InitMcOiRt, MPVCMC_SetCcnt, MPVUMC_EndOfFrame,
  // MPVUMC_Finish, MPVUMC_InitOutRfb have recovered bodies in
  // cri/sofdec/SofdecMpvRuntime.cpp, but that file has ~25 struct-layout
  // assertion failures (SfmpvHandleRuntimeView and siblings) and missing
  // helpers (sfmpv_SkipFrm, sfmpv_ConcatSub). Keep these as no-op stubs
  // until the Mpv runtime struct layouts are reconciled.
  // REAL BODIES now live in cri/sofdec/SofdecMpvRuntime.cpp (ClCompile):
  // MPVCMC_InitMcOiRt, MPVCMC_SetCcnt, MPVUMC_EndOfFrame, MPVUMC_Finish,
  // MPVUMC_InitOutRfb.
  void* MWSFCRE_DestroySfd() { return nullptr; }
  // MWSFCRE_SetSupplySj (0x00AC7D80): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. As a no-arg stub it silently
  // satisfied every `MWSFCRE_SetSupplySj(ply)` call, so the SFD's input lane
  // was never bound to the stream SJ ring. `mwsfcre_CalcWorkStmBuf` reports
  // `sib = 0` on purpose, which leaves SFBUF lane 0 "awaiting supply" - this
  // function is what hands it the ring. Without it the demuxer parsed an empty
  // ring on every server tick and no movie ever produced a frame.
  // MWSFD_GetUsePicUsr (0x00AC9350) reads the library's use-picture-user-data
  // lane; recovered in cri/sofdec/SofdecAdxPlatformRuntime.cpp next to the
  // frame-info conversion that is its only real caller.
  // MWSFD_IsEnableHndl (0x00ACBA10) is recovered in SofdecFoundationRuntime.cpp.
  // Its stub took no arguments, so C linkage let it satisfy every
  // MWSFD_IsEnableHndl(ply) call while always answering "not enabled" -- which
  // is why a successfully created playback handle still drew "handle is
  // invalid" from mwPlyGetStat, mwPlySetFrmSync and mwPlyStartFname alike.
  void* MWSFD_SetCond() { return nullptr; }
  void* MWSFD_SetReqSvrBdrHn() { return nullptr; }
  void* MWSFPLY_SetFlowLimit() { return nullptr; }
  // MWSFSVM_Error: real body in SofdecSvmTransferRuntime.cpp.
  void* MWSFSVM_GotoIdleBorder() { return nullptr; }
  // MWSFSVR_MainThrdProc (0x00AD9230), MWSFSVR_IdleThrdProc (0x00AD9250) and
  // MWSFSVR_VsyncThrdProc (0x00AD9220): real bodies in
  // SofdecAdxPlatformRuntime.cpp. These are the Sofdec worker-thread bodies;
  // while they were stubs nothing ticked the SFD decode server, so no movie
  // frame was ever decoded.
  void* MWSFSVR_CheckForceSvrBdr() { return nullptr; }
  // MWSFSVR_SetMwsfdSvrFlg (0x00AD9870): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. This releases the decode-server
  // gate; while it was a no-op stub the first decode pass latched the gate and
  // no later pass ever got past it.
  void* MWSST_Destroy() { return nullptr; }
  void* MWSST_GetStat() { return nullptr; }
  // MWSST_Stop (0x00AD9C10), MWSST_Pause (0x00AD9CC0): real bodies in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // The MWSTM family (0x00AD90D0 / 0x00AD91A0 / 0x00AD9150 / 0x00AD9160 /
  // 0x00AD9110) now has real bodies in cri/sofdec/SofdecAdxPlatformRuntime.cpp
  // next to MWSTM_Create. Each is a thin wrapper over ADXSTM, and all five were
  // no-arg stubs: MWSTM_SetFileRange bound the streamer to nothing,
  // MWSTM_ReqStart answered 0 ("started") without starting anything, and
  // MWSTM_GetStat answered 0 forever. The SJ ring therefore stayed empty, the
  // MPS demuxer consumed 0 bytes per server tick, and every movie sat in
  // "Preparing" until the process was killed.
  void* SFADXT_SetAudioStreamType() { return nullptr; }
  void* SFAOAP_SetSpeed() { return nullptr; }
  void* SFD_tr_ad_adxt() { return nullptr; }
  void* SFHDS_Finish() { return nullptr; }
  // SFHDS_FinishFhd: real body in SofdecSfdRuntime.cpp (0x00AE7190).
  void* SFHDS_GetMuxVerNum() { return nullptr; }
  // SFHDS_Init: real body in SofdecSfdRuntime.cpp (0x00AE7150).
  // SFHDS_InitFhd: real body in SofdecSfdRuntime.cpp (0x00AE7170). Another
  // no-argument stub that C linkage let stand in for the real one-parameter
  // function, so no file-header record was ever reset.
  // SFHDS_IsSfdHeader: real body in SofdecSfdRuntime.cpp (0x00AE7280).
  // SFHDS_ProcessHdr: real body in SofdecSfdRuntime.cpp (0x00AE7400). It was a
  // no-argument stub here, and because C linkage ignores parameters when
  // mangling it silently satisfied the properly-declared call in
  // sfcre_ProcessHdr - so the SFD header-valid flag was never set and every
  // movie was rejected as "not a valid SFD file".
  void* SFHDS_ReprocessHdr() { return nullptr; }
  void* SFHDS_SetHdr() { return nullptr; }
  // SFH_Destroy: real body in SofdecSfdRuntime.cpp (0x00ADC7D0).
  // SFH_IsSfdHeader: real body in SofdecSfdRuntime.cpp (0x00ADC890).
  // SFMPVF_GetNumFrm now has real body in SofdecMpvRuntime.cpp (compiled).
  // SFPLY_DecideSvrStat: real body now in SofdecSfdRuntime.cpp (was named lowercase `sfply_DecideSvrStat`; renamed to match callers).
  // SFTIM_InitTcode, SFTIM_InitTtu: real bodies in SofdecMpvRuntime.cpp.
  void* SFXLIB_Error() { return nullptr; }
  void* SFXZ_Destroy() { return nullptr; }
  void* SFXZ_GetZfrmRange() { return nullptr; }
  void* SFXZ_IsSetZclip() { return nullptr; }
  void* SFX_DecideTableAlph3() { return nullptr; }
  void* SFX_GetCompoMode() { return nullptr; }
  void* SFX_MakeTable() { return nullptr; }
  // SFX_SetOutBufSize (0x00ACCD50): real body in SofdecSfxRuntime.cpp.
  void* SFX_SetUnitWidth() { return nullptr; }
  void* SFX_SetZbit() { return nullptr; }
  void* SUD_AnalyTypeCcs() { return nullptr; }
  void* SUD_Finish() { return nullptr; }
  void* SUD_Init() { return nullptr; }
  // UTY_MemsetDword: real body in SofdecMpvRuntime.cpp.
  void* adxf_GetPtStat() { return nullptr; }
  void* adxf_LoadPtBothNw() { return nullptr; }
  void* adxf_ReadNw32() { return nullptr; }
  void* adxf_ReadSj32() { return nullptr; }
  void* adxf_Seek() { return nullptr; }
  void* adxf_SetFileInfoEx() { return nullptr; }
  void* adxf_Stop() { return nullptr; }
  void* adxt_Create() { return nullptr; }
  void* adxt_ExecHndl() { return nullptr; }
  void* adxt_GetTime() { return nullptr; }
  void* adxt_Pause() { return nullptr; }
  void* ahxexecfunc() { return nullptr; }
  void* ahxsetsjifunc() { return nullptr; }
  void* ahxtermsupplyfunc() { return nullptr; }
  void* cft_c_Ycc420plnToArgb8888Int1smp() { return nullptr; }
  void* cft_c_Ycc420plnToArgb8888Prg1smp() { return nullptr; }
  // cft_mmx_Ycc420plnToArgb8888UserTable (0x00AF3040) and
  // cft_sse_Ycc420plnToArgb8888UserTable (0x00AF2B20): real bodies in
  // SofdecSvmTransferRuntime.cpp. These are the kernels that write the movie's
  // pixels. While they stood as C-linkage stubs the whole pipeline reported
  // success - the frame decoded, the texture was locked and unlocked - and
  // every frame came out transparent black.
  void* cft_sse_Ycc420plnToArgb8888Int1smp() { return nullptr; }
  void* decodeTsSub() { return nullptr; }
  // mpvcmc_InitMcOiTa: real body in SofdecMpvRuntime.cpp.
  void* mpvhdec_ReadKernelIntraIdcPrec3() { return nullptr; }
  void* mwPlyFinishSfdFx() { return nullptr; }
  // mwPlyInitSfdFx: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp, next
  // to mwPlySfdInit. The SFD transfer strategy table it depends on
  // (mwsfd_initsfdpara.callbacks -> 0x00D7F3D0) is now modelled at the end of
  // cri/sofdec/SofdecSfdRuntime.cpp.
  void* mwPlyIsNextFrmReady() { return nullptr; }
  // mwPlyPause (0x00ACB220): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. CMovie arms the pause in
  // OpenMovie and releases it in PlayMovie; while this was a stub neither call
  // did anything and playback could never be resumed.
  // mwPlySfdStart (0x00ACADA0): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. This is what calls SFD_Start, so
  // while it was a stub the SFPLY phase lane never left STOP.
  void* mwRnaCreate() { return nullptr; }
  // mw_sfd_start_ex (0x00ACAF40): real body in
  // cri/sofdec/SofdecAdxPlatformRuntime.cpp. This is the shared tail of every
  // playback start; it reaches mwPlySfdStandby, the only path that writes the
  // SFPLY phase lane. While it was a stub the machine never left STOP.
  // mwl_convFrmInfFromSFD (0x00ACA210) is what fills the outgoing frame info -
  // including the frame buffer address CMovie::UploadCurrentFrameToTexture
  // reads, which stayed null for every frame while this stub stood. Recovered
  // in cri/sofdec/SofdecAdxPlatformRuntime.cpp with its four mwsffrm_* helpers.
  // mwsfcre_AllFree: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // mwsfcre_DecideFtypeByHdrInf: real body in moho/misc/StartupHelpers.cpp,
  // next to its only caller mwPlyGetHdrInf (adjacent addresses 0x00AC8F00 /
  // 0x00AC8DF0 - same original translation unit).
  // mwsfcre_GetMallocCnt: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // mwsfcre_IncMallocCnt: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // mwsfcre_OrgMalloc: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // mwsfcre_UsrMalloc: real body in cri/sofdec/SofdecAdxPlatformRuntime.cpp.
  // mwsfdcre_IsPlayableByHdrInf: real body in moho/misc/StartupHelpers.cpp
  // (0x00AC8F30, same original translation unit as mwPlyGetHdrInf).
  void* mwsffrm_AnalyFxType() { return nullptr; }
  void* mwsffrm_AnalyTotalFrm() { return nullptr; }
  void* mwsffrm_CheckAinf() { return nullptr; }
  void* mwsffrm_GetNumAudioCh() { return nullptr; }
  void* mwsffrm_GetNumVideoCh() { return nullptr; }
  void* mwsffrm_SaveFrmDetail() { return nullptr; }
  void* mwsffrm_SetFrmApi() { return nullptr; }
  void* parse_PES_packet_sub() { return nullptr; }
  void* sfcre_AnalyMpa() { return nullptr; }
  // sfmpvf_IsChkFirst, sfmpvf_SetPicUsrBuf: real bodies in SofdecMpvRuntime.cpp.
  // sfply_ExecOne (0x00AD6F00): real body in SofdecSfdRuntime.cpp. This is the
  // SFD playback state-machine pump. While it was a stub the machine never
  // advanced, nothing was ever decoded, and every movie stayed black even
  // though all five state handlers already had real bodies.
  // sfply_InitHn: real body in SofdecSfdRuntime.cpp (0x00AD7AE0). While this
  // stub stood, sfply_Create always returned null and every movie failed with
  // "E2012 mwPlyCreate:can't create SFD".
  void* sfply_ResetHn() { return nullptr; }
  // sfxcnv_ExecCnvFrmByCbFunc (0x00ACEB10): real body in SofdecSfxRuntime.cpp.
  // This is where a decoded frame becomes pixels. While it stood as a stub the
  // whole conversion path completed and reported success without ever writing
  // to the destination surface.
  void* sfxcnv_ExecFullAlphaByCbFunc() { return nullptr; }
  void* sfxcnv_MakeZTbl() { return nullptr; }
  // mpvhdec_ReadKernelIntraDefault (0x00AFAE50) and
  // mpvhdec_ReadKernelPredictedDefault (0x00AFD7C0) are recovered in
  // moho/movie/MPVDecoder.cpp. While these stubs stood, every block came back
  // with no coefficients at all, so the decoder ran without ever producing a
  // picture.
  // sub_C0E1B0 / sub_C0E2E0 are the intra and predicted macroblock scan-state
  // initializers. Their real bodies were already recovered as
  // MPVDEC_InitScanStateIntra / MPVDEC_InitScanStatePredicted in
  // moho/movie/MPVDecoder.cpp but nothing referenced them - mpvhdec_DecPscSj
  // installed these stubs as the picture's read drivers instead, so every
  // macroblock came back with no coefficients. Wired up at the install site.

  // C-linkage stubs for callers in MPVDecoder.cpp (now extern "C") whose real
  // bodies aren't in any compiled Sofdec source. Return 0 as no-op.
  int mpvcdec_InitDct() { return 0; }
  int M2VAPRD_Init() { return 0; }

  // New stubs introduced by SofdecMpvRuntime.cpp going live. These are
  // referenced by the newly-compiled MPV runtime but their real bodies are
  // in different Sofdec sources that are still not compiled.
  // MPV_Init (0x00AE7950) is recovered in moho/movie/MPVDecoder.cpp, next to
  // the fan-out it drives. Its stub here took no arguments, so C linkage let it
  // silently satisfy SFMPV_Init's two-argument call while returning success
  // without initializing a single decoder stage.
  int MPV_IsEmptyBpic(int) { return 0; }
  int MPV_IsEmptyPpic(int) { return 0; }
  // sfmpv_ExecServerSub (0x00AD1C10) is the MPV decode-server tick - the whole
  // video decode path hangs off it, and while it was stubbed no picture was
  // ever decoded and sfmpv_ChkPrepFlg never latched the video-output lane's
  // prep flag, so SFPLY sat in PREP forever. Recovered next to the rest of the
  // MPV server lane in cri/sofdec/SofdecMpvRuntime.cpp.
}

// SofdecMpv data globals — referenced by newly-compiled SofdecMpvRuntime.
// These live in .bss/.data in the FA binary; we provide zero-initialised
// stand-ins so the link succeeds. Movies won't play until recovered.
extern "C" {
  // sfmpv_fps_round (0x00D7F60C), sfmpv_conv_29_97 (0x00D7F630) and
  // sfmpv_conv_59_94 (0x00D7F650) are real timecode tables, not scalars. As
  // zeroed ints they made sfmpv_Pts2Tc divide by zero on the first picture
  // header, killing the MPV decode thread outright. Defined from the binary
  // bytes next to sfmpv_Pts2Tc in cri/sofdec/SofdecMpvRuntime.cpp.
  // sfmpv_work is the MPV work arena, not a scalar - a 4-byte stub here meant
  // MPV_Init's 264 KB clear ran straight off the end of it. Sized properly in
  // cri/sofdec/SofdecMpvRuntime.cpp next to SFMPV_Init, its only real user.
  int sfmpv_discard_wsiz = 0;
  void* sfmpv_picusr_pbuf = nullptr;
  int sfmpv_picusr_bufnum = 0;
  int sfmpv_picusr_buf1siz = 0;
}

// === Function-pointer globals (nulled) ===
extern "C" {
  void(*ahxsetdecsmplfunc)(void*, std::int32_t) = nullptr;
  void(*ahxsetextfunc)(void*, const std::int16_t*) = nullptr;
  std::int32_t(*SFPLY_SetPtsInfo)(std::int32_t, std::int32_t*) = nullptr;
  // conceal_fn_tbl (0x00D7FFFC) is a real four-entry dispatch table, not a
  // zeroed buffer. MPVCONCEAL_StartFrame installs one of its slots as the
  // handle's macroblock-discontinuity handler, so a null slot meant the first
  // discontinuity in any picture called through a null pointer. Defined next
  // to its four handlers in moho/movie/MPVDecoder.cpp.
}

// SFD_tr_sd_m2ts / SFD_tr_sd_mps / SFD_tr_vd_mpv are the binary's names for
// three recovered transfer-strategy descriptors; they now live in
// cri/sofdec/SofdecSfdRuntime.cpp instead of being zeroed here.
// === Data stubs (zero-init 4 KB buffers) ===
extern "C" {
  std::uint8_t AdxQtbl[4096] = {};
  std::uint8_t AdxQtblFloat0[4096] = {};
  std::uint8_t AdxQtblFloat1[4096] = {};
  std::uint8_t M2T_libobj[4096] = {};
  // SFTIM_prate (0x00D7FA28) is a real 10-entry milli-fps table, not a buffer;
  // zeroed here it made every timecode convert to zero. Defined from the binary
  // bytes next to SFTIM_Tc2Time in cri/sofdec/SofdecSfdRuntime.cpp.
  std::uint8_t adxt_q12_mix_table[4096] = {};
  std::uint8_t alloc_len_08sb[4096] = {};
  std::uint8_t alloc_len_12sb[4096] = {};
  std::uint8_t alloc_len_27sb[4096] = {};
  std::uint8_t alloc_len_30sb[4096] = {};
  std::uint8_t book[4096] = {};
  std::uint8_t cri_verstr_ptr_m2spes[4096] = {};
  std::uint8_t cri_verstr_ptr_m2t[4096] = {};
  std::uint8_t dolby_long[4096] = {};
  std::uint8_t dolby_short[4096] = {};
  std::uint8_t dolby_start[4096] = {};
  std::uint8_t dolby_stop[4096] = {};
  std::uint8_t flt_1204CFC[4096] = {};
  std::uint8_t flt_12054FC[4096] = {};
  std::uint8_t flt_1205AFC[4096] = {};
  std::uint8_t flt_1205B00[4096] = {};
  std::uint8_t flt_120ABFC[4096] = {};
  std::uint8_t huffman_codebook[4096] = {};
  std::uint8_t m2adec_frequency_table[4096] = {};
  std::uint8_t m2adec_num_spectra_per_sfb[4096] = {};
  std::uint8_t m2adec_num_spectra_per_sfb8[4096] = {};
  std::uint8_t m2adec_tns_decode_table[4096] = {};
  std::uint8_t m2aimdct_cos_table_long[4096] = {};
  std::uint8_t m2aimdct_cos_table_long_m4[4096] = {};
  std::uint8_t m2aimdct_cos_table_short[4096] = {};
  std::uint8_t m2aimdct_pcm256[4096] = {};
  std::uint8_t m2aimdct_sin_table_long[4096] = {};
  std::uint8_t m2aimdct_sin_table_long_m4[4096] = {};
  std::uint8_t m2aimdct_sin_table_short[4096] = {};
  std::uint8_t m2aimdct_sorted[4096] = {};
  std::uint8_t m2aimdct_work[4096] = {};
  std::uint8_t m2tsd_outsj[4096] = {};
  std::uint8_t m2tsd_relaysj[4096] = {};
  std::uint8_t mpadcd_10bit_mixed_smpl1[4096] = {};
  std::uint8_t mpadcd_10bit_mixed_smpl2[4096] = {};
  std::uint8_t mpadcd_10bit_mixed_smpl3[4096] = {};
  std::uint8_t mpadcd_5bit_mixed_smpl1[4096] = {};
  std::uint8_t mpadcd_5bit_mixed_smpl2[4096] = {};
  std::uint8_t mpadcd_5bit_mixed_smpl3[4096] = {};
  std::uint8_t mpadcd_7bit_mixed_smpl1[4096] = {};
  std::uint8_t mpadcd_7bit_mixed_smpl2[4096] = {};
  std::uint8_t mpadcd_7bit_mixed_smpl3[4096] = {};
  std::uint8_t mpadcd_bits_type1_2bit[4096] = {};
  std::uint8_t mpadcd_bits_type1_3bit[4096] = {};
  std::uint8_t mpadcd_bits_type1_4bit_high[4096] = {};
  std::uint8_t mpadcd_bits_type1_4bit_low[4096] = {};
  std::uint8_t mpadcd_bps_table[4096] = {};
  std::uint8_t mpadcd_dequantize_denormze_table[4096] = {};
  std::uint8_t mpadcd_dequantize_table_d[4096] = {};
  std::uint8_t mpadcd_division_table[4096] = {};
  std::uint8_t mpadcd_freq_table[4096] = {};
  std::uint8_t mpadcd_group_type1_high[4096] = {};
  std::uint8_t mpadcd_jsb_table[4096] = {};
  std::uint8_t mpadcd_quant_type1_3bit[4096] = {};
  std::uint8_t mpadcd_quant_type1_4bit_high[4096] = {};
  std::uint8_t mpadcd_quant_type1_4bit_low[4096] = {};
  std::uint8_t mpadcd_synthesis_filter_table[4096] = {};
  std::uint8_t mpadcd_synthesis_polyphase_seed_table[4096] = {};
  std::uint8_t mpadcd_synthesis_window_table[4096] = {};
  std::uint8_t mpadcd_synthesis_window_tail_table[4096] = {};
  std::uint8_t mpv_clip_0_255_base[4096] = {};
  std::uint8_t mpv_clip_0_255_tbl[4096] = {};
  // mpvlib_cond_dfl (0x00D7FC80) is real .rdata, not BSS - it is recovered
  // with its true contents in moho/movie/MPVDecoder.cpp. The zero blob that
  // used to stand in here silently handed every decoder handle null condition
  // defaults, including a null conceal callback.
  std::uint8_t mpvlib_libwork[4096] = {};
  std::uint8_t mpvvlc2_c_dcsiz[4096] = {};
  std::uint8_t mpvvlc2_y_dcsiz[4096] = {};
  std::uint8_t mpvvlc_b_mbtype[4096] = {};
  std::uint8_t mpvvlc_c_dcsiz[4096] = {};
  std::uint8_t mpvvlc_cbp[4096] = {};
  std::uint8_t mpvvlc_mbai_b_0[4096] = {};
  std::uint8_t mpvvlc_mbai_b_1[4096] = {};
  std::uint8_t mpvvlc_mbai_i_0[4096] = {};
  std::uint8_t mpvvlc_mbai_i_1[4096] = {};
  std::uint8_t mpvvlc_mbai_p_0[4096] = {};
  std::uint8_t mpvvlc_mbai_p_1[4096] = {};
  std::uint8_t mpvvlc_motion_0[4096] = {};
  std::uint8_t mpvvlc_motion_1[4096] = {};
  std::uint8_t mpvvlc_p_mbtype[4096] = {};
  std::uint8_t mpvvlc_run_level_0a[4096] = {};
  std::uint8_t mpvvlc_run_level_0b[4096] = {};
  std::uint8_t mpvvlc_run_level_0c[4096] = {};
  std::uint8_t mpvvlc_run_level_1[4096] = {};
  std::uint8_t mpvvlc_run_level_2[4096] = {};
  std::uint8_t mpvvlc_run_level_4[4096] = {};
  std::uint8_t mpvvlc_run_level_8[4096] = {};
  std::uint8_t mpvvlc_y_dcsiz[4096] = {};
  std::uint8_t mpvvlt2_c_dcsiz[4096] = {};
  std::uint8_t mpvvlt2_y_dcsiz[4096] = {};
  std::uint8_t mpvvlt_b_mbtype[4096] = {};
  std::uint8_t mpvvlt_c_dcsiz[4096] = {};
  std::uint8_t mpvvlt_cbp[4096] = {};
  std::uint8_t mpvvlt_mbai_b_0[4096] = {};
  std::uint8_t mpvvlt_mbai_b_1[4096] = {};
  std::uint8_t mpvvlt_mbai_i_0[4096] = {};
  std::uint8_t mpvvlt_mbai_i_1[4096] = {};
  std::uint8_t mpvvlt_mbai_p_0[4096] = {};
  std::uint8_t mpvvlt_mbai_p_1[4096] = {};
  std::uint8_t mpvvlt_motion_0[4096] = {};
  std::uint8_t mpvvlt_motion_1[4096] = {};
  std::uint8_t mpvvlt_p_mbtype[4096] = {};
  std::uint8_t mpvvlt_y_dcsiz[4096] = {};
  std::uint8_t mwsfd_init_flag[4096] = {};
  std::uint8_t sSofDec_tabs[4096] = {};
  std::uint8_t sfcre_fhd[4096] = {};
  std::uint8_t sfcre_mpv_picrate[4096] = {};
  std::uint8_t sfh_workinfo[4096] = {};
  std::uint8_t sfmpv_para[4096] = {};
  std::uint8_t sfmpv_rfb_adr_tbl[4096] = {};
  // sftim_tc2time (0x00D7FA50) is an 18-entry converter dispatch table, not a
  // buffer. Zeroed here, SFTIM_Tc2Time found a null slot for every frame rate
  // and raised FF000221 forever. Defined from the binary bytes next to the
  // converters in cri/sofdec/SofdecSfdRuntime.cpp.
  std::uint8_t sin_long[4096] = {};
  std::uint8_t sin_short[4096] = {};
  std::uint8_t sin_start[4096] = {};
  std::uint8_t sin_stop[4096] = {};
  std::uint8_t skg_prim_tbl[4096] = {};
  std::uint8_t spectra_huffman_codebook_parameters[4096] = {};
  std::uint8_t xeci_is_done[4096] = {};
  std::uint8_t xeci_old_thread_prio[4096] = {};
  std::uint8_t xeci_thread[4096] = {};
}

// === C++ mangled Sofdec functions ===
// REMOVED: DCT_*, M2V_*, M2VAPRD_Init were here as C++-mangled stubs that
// shadowed the real recovered C-linkage definitions in moho/audio/SofdecRuntime.cpp's
// translation-unit assembly. The caller (MPVDecoder.cpp) now declares them
// `extern "C"` so its calls resolve to the real bodies. mpvcdec_InitDct also
// had an EngineUnrecoveredStubs stub; same fix applies (extern "C" on caller).

// === C++ mangled Sofdec function pointers in moho:: namespace ===
namespace moho {
  struct MwsfdPlaybackStateSubobj;
  struct MwsfdFrameInfo;
}
int mwPlyGetSubtitle(moho::MwsfdPlaybackStateSubobj*, char*, int, int*) { return 0; }
int mwPlyIsPause(moho::MwsfdPlaybackStateSubobj*) { return 0; }
int mwPlyPause(moho::MwsfdPlaybackStateSubobj*, int) { return 0; }
// mwPlyFxCnvFrmARGB8888 (0x00ACC6E0): real body in cri/sofdec/SofdecSfxRuntime.cpp.
// While this empty body stood, CMovie locked its texture sheet, wrote
// nothing and unlocked it, so every movie frame arrived transparent black.
