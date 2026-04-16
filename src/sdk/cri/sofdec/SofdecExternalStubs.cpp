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
// in-range but yield zeros. Real data tables live as .rdata in the FA
// binary — recovering them requires reading fixed-size arrays from the
// binary at each symbol's address.

#include <cstdint>

// === Function stubs (cdecl no-arg, return 0/null) ===
extern "C" {
  void* ADXM_Finish() { return nullptr; }
  void* ADXM_SetupThrd() { return nullptr; }
  void* ADXM_WaitVsync() { return nullptr; }
  void* ADXPC_SetupSoundDirectSound8() { return nullptr; }
  void* ADXRNA_ExecHndl() { return nullptr; }
  void* ADXT_AttachDolbyProLogicII() { return nullptr; }
  void* ADXT_DetachMPEG2AAC() { return nullptr; }
  void* ADXT_Init() { return nullptr; }
  void* CRIERR_CallErr() { return nullptr; }
  void* M2TSD_Init() { return nullptr; }
  void* M2T_Create() { return nullptr; }
  void* MPS_Create() { return nullptr; }
  void* MPS_DecHd() { return nullptr; }
  void* MPS_Destroy() { return nullptr; }
  void* MPS_Finish() { return nullptr; }
  void* MPS_GetElementaryInfo() { return nullptr; }
  void* MPS_GetLastSysHd() { return nullptr; }
  void* MPS_GetPackHd() { return nullptr; }
  void* MPS_GetPketHd() { return nullptr; }
  void* MPS_GetSysHd() { return nullptr; }
  void* MPS_SetPesFn() { return nullptr; }
  void* MPS_SetPesSw() { return nullptr; }
  void* MPS_SetPsMapFn() { return nullptr; }
  void* MPS_SetSystemFn() { return nullptr; }
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
  void* MWSFCRE_SetSupplySj() { return nullptr; }
  void* MWSFD_GetUsePicUsr() { return nullptr; }
  void* MWSFD_IsEnableHndl() { return nullptr; }
  void* MWSFD_SetCond() { return nullptr; }
  void* MWSFD_SetReqSvrBdrHn() { return nullptr; }
  void* MWSFPLY_SetFlowLimit() { return nullptr; }
  void* MWSFSVM_Error() { return nullptr; }
  void* MWSFSVM_GotoIdleBorder() { return nullptr; }
  void* MWSFSVR_CheckForceSvrBdr() { return nullptr; }
  void* MWSFSVR_IdleThrdProc() { return nullptr; }
  void* MWSFSVR_MainThrdProc() { return nullptr; }
  void* MWSFSVR_SetMwsfdSvrFlg() { return nullptr; }
  void* MWSFSVR_VsyncThrdProc() { return nullptr; }
  void* MWSST_Destroy() { return nullptr; }
  void* MWSST_GetStat() { return nullptr; }
  void* MWSST_Pause() { return nullptr; }
  void* MWSST_Stop() { return nullptr; }
  void* MWSTM_Destroy() { return nullptr; }
  void* MWSTM_GetStat() { return nullptr; }
  void* MWSTM_ReqStart() { return nullptr; }
  void* MWSTM_ReqStop() { return nullptr; }
  void* MWSTM_SetFileRange() { return nullptr; }
  void* SFADXT_SetAudioStreamType() { return nullptr; }
  void* SFAOAP_SetSpeed() { return nullptr; }
  void* SFD_tr_ad_adxt() { return nullptr; }
  void* SFHDS_Finish() { return nullptr; }
  void* SFHDS_FinishFhd() { return nullptr; }
  void* SFHDS_GetMuxVerNum() { return nullptr; }
  void* SFHDS_Init() { return nullptr; }
  void* SFHDS_InitFhd() { return nullptr; }
  void* SFHDS_IsSfdHeader() { return nullptr; }
  void* SFHDS_ProcessHdr() { return nullptr; }
  void* SFHDS_ReprocessHdr() { return nullptr; }
  void* SFHDS_SetHdr() { return nullptr; }
  void* SFH_Destroy() { return nullptr; }
  void* SFH_IsSfdHeader() { return nullptr; }
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
  void* SFX_SetOutBufSize() { return nullptr; }
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
  void* cft_mmx_Ycc420plnToArgb8888UserTable() { return nullptr; }
  void* cft_sse_Ycc420plnToArgb8888Int1smp() { return nullptr; }
  void* cft_sse_Ycc420plnToArgb8888UserTable() { return nullptr; }
  void* decodeTsSub() { return nullptr; }
  // mpvcmc_InitMcOiTa: real body in SofdecMpvRuntime.cpp.
  void* mpvhdec_ReadKernelIntraIdcPrec3() { return nullptr; }
  void* mwPlyFinishSfdFx() { return nullptr; }
  void* mwPlyInitSfdFx() { return nullptr; }
  void* mwPlyIsNextFrmReady() { return nullptr; }
  void* mwPlyPause() { return nullptr; }
  void* mwPlySfdStart() { return nullptr; }
  void* mwRnaCreate() { return nullptr; }
  void* mw_sfd_start_ex() { return nullptr; }
  void* mwl_convFrmInfFromSFD() { return nullptr; }
  void* mwsfcre_AllFree() { return nullptr; }
  void* mwsfcre_DecideFtypeByHdrInf() { return nullptr; }
  void* mwsfcre_GetMallocCnt() { return nullptr; }
  void* mwsfcre_IncMallocCnt() { return nullptr; }
  void* mwsfcre_OrgMalloc() { return nullptr; }
  void* mwsfcre_UsrMalloc() { return nullptr; }
  void* mwsfdcre_IsPlayableByHdrInf() { return nullptr; }
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
  void* sfply_ExecOne() { return nullptr; }
  void* sfply_InitHn() { return nullptr; }
  void* sfply_ResetHn() { return nullptr; }
  void* sfxcnv_ExecCnvFrmByCbFunc() { return nullptr; }
  void* sfxcnv_ExecFullAlphaByCbFunc() { return nullptr; }
  void* sfxcnv_MakeZTbl() { return nullptr; }
  void* sub_AFAE50() { return nullptr; }
  void* sub_AFD7C0() { return nullptr; }
  void* sub_C0E1B0() { return nullptr; }
  void* sub_C0E2E0() { return nullptr; }

  // C-linkage stubs for callers in MPVDecoder.cpp (now extern "C") whose real
  // bodies aren't in any compiled Sofdec source. Return 0 as no-op.
  int mpvcdec_InitDct() { return 0; }
  int M2VAPRD_Init() { return 0; }

  // New stubs introduced by SofdecMpvRuntime.cpp going live. These are
  // referenced by the newly-compiled MPV runtime but their real bodies are
  // in different Sofdec sources that are still not compiled.
  int MPV_Init() { return 0; }
  int MPV_IsEmptyBpic(int) { return 0; }
  int MPV_IsEmptyPpic(int) { return 0; }
  int sfmpv_ExecServerSub(int) { return 0; }
}

// SofdecMpv data globals — referenced by newly-compiled SofdecMpvRuntime.
// These live in .bss/.data in the FA binary; we provide zero-initialised
// stand-ins so the link succeeds. Movies won't play until recovered.
extern "C" {
  int sfmpv_fps_round = 0;
  int sfmpv_conv_29_97 = 0;
  int sfmpv_conv_59_94 = 0;
  int sfmpv_work = 0;
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
  int(*conceal_fn_tbl[256])(int) = {};
}

// === Data stubs (zero-init 4 KB buffers) ===
extern "C" {
  std::uint8_t AdxQtbl[4096] = {};
  std::uint8_t AdxQtblFloat0[4096] = {};
  std::uint8_t AdxQtblFloat1[4096] = {};
  std::uint8_t M2T_libobj[4096] = {};
  std::uint8_t SFD_tr_sd_m2ts[4096] = {};
  std::uint8_t SFD_tr_sd_mps[4096] = {};
  std::uint8_t SFD_tr_vd_mpv[4096] = {};
  std::uint8_t SFTIM_prate[4096] = {};
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
  std::uint8_t mpvlib_cond_dfl[4096] = {};
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
  std::uint8_t mpvvlt_run_level_0a[4096] = {};
  std::uint8_t mpvvlt_run_level_0b[4096] = {};
  std::uint8_t mpvvlt_run_level_0c[4096] = {};
  std::uint8_t mpvvlt_run_level_1[4096] = {};
  std::uint8_t mpvvlt_run_level_2[4096] = {};
  std::uint8_t mpvvlt_run_level_4[4096] = {};
  std::uint8_t mpvvlt_y_dcsiz[4096] = {};
  std::uint8_t mwsfd_init_flag[4096] = {};
  std::uint8_t sSofDec_tabs[4096] = {};
  std::uint8_t sfcre_fhd[4096] = {};
  std::uint8_t sfcre_mpv_picrate[4096] = {};
  std::uint8_t sfh_workinfo[4096] = {};
  std::uint8_t sfmpv_para[4096] = {};
  std::uint8_t sfmpv_rfb_adr_tbl[4096] = {};
  std::uint8_t sftim_tc2time[4096] = {};
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
void mwPlyFxCnvFrmARGB8888(moho::MwsfdPlaybackStateSubobj*, const moho::MwsfdFrameInfo*, void*) {}
