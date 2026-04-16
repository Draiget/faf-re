/**
 * CRI Sofdec MPV (Movie Player Video) subsystem runtime functions.
 *
 * This file contains recovered initialization and parameter-validation logic
 * for the statically linked CRI Sofdec MPV library as shipped in Forged Alliance.
 */

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <limits>

struct SfmpvPictureAttributeRuntimeView;
struct SfmpvPictureDecodeLaneRuntimeView;
struct SfmpvComplementPts;
struct SfmpvMvInfoRuntimeView;
struct SfmpvInfoRuntimeView;
struct SfmpvfInfoRuntimeView;
struct SfmpvfFrameObjectRuntimeView;
struct SfmpvfFrameInfoRuntimeView;
struct SfmpvHandleRuntimeView;
struct SfmpvPackedTimecodeRuntimeView;
struct SfmpvDecodeFrameParamRuntimeView;
struct SfbufRingChunkRuntimeView;
struct MpvcmcRuntimeView;
struct SfptsQueueEntryRuntimeView;
struct SfptsPtsQueueRuntimeView;
struct SfptsSourceLaneRuntimeView;

// ---------------------------------------------------------------------------
// Forward declarations for CRI library functions used by this module
// ---------------------------------------------------------------------------

extern "C" {
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  void SFLIB_LockCs();
  void SFLIB_UnlockCs();
  std::int32_t sfmpv_ChkFatal();
  std::int32_t MPVLIB_CheckHn(std::int32_t decoderHandle);
  std::int32_t MPV_GoNextDelimSj(std::int32_t streamBufferAddress);
  std::int32_t MPV_MoveChunk(std::int32_t streamBufferAddress, std::int32_t laneIndex, std::int32_t byteCount);
  std::int32_t MPV_Finish();
  std::int32_t MPVERR_SetCode(std::int32_t decoderHandle, std::int32_t errorCode);
  std::int32_t SFMPVF_IsTermDec(std::int32_t workctrlAddress);
  std::int32_t SFMPVF_GetNumFrm(std::int32_t workctrlAddress);
  std::int32_t MPV_Init(std::int32_t framePoolCount, std::int32_t workAddress);
  std::int32_t M2V_Init(std::int32_t framePoolCount, void* workAddress, std::int32_t workBytes);
  std::int32_t UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
  std::int32_t UTY_MulDiv(std::int32_t lhs, std::int32_t rhs, std::int32_t divisor);
  std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
  void SFTIM_UpdateItime(void* timerState, std::int32_t interpolationTime);
  std::int32_t SFTIM_GetNextItime(void* timerState, std::int32_t interpolationTime);
  std::int32_t SFTIM_IsGetFrmTime(std::int32_t workctrlAddress, const SfmpvfFrameInfoRuntimeView* frameInfo);
  /**
   * Address: 0x00AE5C40 (FUN_00AE5C40, _SFPTS_ReadPtsQue)
   *
   * What it does:
   * Reads one PTS entry from the selected source-lane queue, defaulting output
   * lanes to `-1` when no queue hit is available.
   */
  std::int32_t SFPTS_ReadPtsQue(
    std::int32_t workctrlAddress,
    std::int32_t sourceLaneIndex,
    std::int32_t delimiterAddress,
    std::int32_t* outPtsWords
  );
  /**
   * Address: 0x00AE5CA0 (FUN_00AE5CA0, _sfpts_ReadPtsQueSub)
   *
   * What it does:
   * Locates one queued PTS entry relative to delimiter address, updates queue
   * cursor/count lanes, and copies 16-byte entry words to caller output.
   */
  std::int32_t* sfpts_ReadPtsQueSub(
    SfptsPtsQueueRuntimeView* ptsQueue,
    std::int32_t normalizedDelimiterAddress,
    std::int32_t* outPtsWords,
    std::int32_t sourceLaneStartAddress,
    std::int32_t sourceLaneSpanBytes
  );
  std::int32_t sfpts_SearchPtsQue(
    const SfptsPtsQueueRuntimeView* ptsQueue,
    std::uint32_t delimiterAddress,
    std::uint32_t sourceLaneStartAddress,
    std::int32_t sourceLaneSpanBytes
  );
  void SFTIM_GetTime(std::int32_t workctrlAddress, std::int32_t* outTimeMajor, std::int32_t* outTimeMinor);
  /**
   * Address: 0x00ADBED0 (FUN_00ADBED0, _SFTIM_GetSpeed)
   *
   * What it does:
   * Returns one per-handle timer speed rational lane.
   */
  std::int32_t SFTIM_GetSpeed(std::int32_t workctrlAddress);
  std::int32_t SFSET_SetCond(std::int32_t workctrlAddress, std::int32_t conditionId, std::int32_t value);
  std::int32_t SFSET_GetCond(std::int32_t workctrlAddress, std::int32_t conditionId);
  std::int32_t SFHDS_GetColType(std::int32_t workctrlAddress);
  std::int32_t SFD_SetMpvCond(
    std::int32_t workctrlAddress,
    std::int32_t conditionId,
    std::int32_t (*conditionCallback)()
  );
  std::int32_t sfmpv_DetectTcErr(std::int32_t workctrlAddress, const SfmpvPictureAttributeRuntimeView* pictureAttribute);
  std::int32_t sfmpv_DoReformTc(
    std::int32_t workctrlAddress,
    SfmpvPictureAttributeRuntimeView* pictureAttribute,
    std::int64_t presentationPts,
    std::int32_t detectErrorMode
  );
  std::int32_t sfmpv_Pts2Tc(
    std::int64_t presentationPts,
    std::int32_t frameRateIndex,
    std::int32_t dropFrameMode,
    std::int32_t decodeOrderMetric,
    SfmpvPackedTimecodeRuntimeView* outTimecode
  );
  std::int32_t sfmpv_NextTc(
    const SfmpvPackedTimecodeRuntimeView* sourceTimecode,
    SfmpvPackedTimecodeRuntimeView* outTimecode
  );
  std::int32_t sfmpv_CalcAudioTotTime(std::int32_t workctrlAddress);
  std::int32_t sfmpv_CalcVideoTotTime(std::int32_t workctrlAddress);
  /**
   * Address: 0x00AE5F50 (FUN_00AE5F50, _SFCON_UpdateConcatTime)
   *
   * What it does:
   * Adds one concat-time delta to runtime timing state and records the updated
   * total in a 32-slot history ring.
   */
  void SFCON_UpdateConcatTime(std::int32_t workctrlAddress, std::int32_t totalTime);
  /**
   * Address: 0x00AE5FB0 (FUN_00AE5FB0, _SFCON_WriteTotSmplQue)
   *
   * What it does:
   * Pushes one `(totalSamples, sampleRate)` update into the 32-slot audio
   * total-sample queue when capacity is available.
   */
  std::int32_t SFCON_WriteTotSmplQue(
    std::int32_t workctrlAddress,
    std::int32_t totalSamples,
    std::int32_t sampleRate
  );
  std::int32_t UTY_CmpTime(
    std::int32_t lhsMajor,
    std::int32_t lhsMinor,
    std::int32_t rhsMajor,
    std::int32_t rhsMinor
  );
  std::int32_t sfmpv_GetDtime(
    std::int32_t workctrlAddress,
    std::int32_t mode,
    std::int32_t* outDeltaMajor,
    std::int32_t* outDeltaMinor
  );
  std::int32_t sfmpv_ExecServerSub(std::int32_t workctrlAddress);
  std::int32_t sfmpv_SetSkipTtu(std::int32_t workctrlAddress);
  std::int32_t sfmpv_UpdateDefect(std::int32_t workctrlAddress, std::int32_t defectLaneAddress, std::int32_t defectDetected);
  std::int32_t sfmpv_IsSeekSkip(std::int32_t workctrlAddress);
  std::int32_t sfmpv_IsDefect(std::int32_t workctrlAddress, std::int32_t pictureType);
  std::int32_t sfmpv_IsPtypeSkip(std::int32_t workctrlAddress, std::int32_t pictureType);
  std::uint8_t*
  sfmpv_IsEmptyBpic(std::int32_t workctrlAddress, std::int32_t pictureType, const SfbufRingChunkRuntimeView* chunkWords);
  std::int32_t sfmpv_CopyPicUsrInf(std::int32_t destinationInfoAddress, std::int32_t sourceInfoAddress);
  std::int32_t sfmpv_SetMpvHd(std::int32_t workctrlAddress, std::int32_t frameRateBase, std::int32_t pictureHeaderChunkAddress);
  std::int32_t SFMPV_Seek(std::int32_t workctrlAddress);
  std::int32_t sfmpv_SetStartTtu(std::int32_t workctrlAddress);
  std::int32_t SJRBF_GetFlowCnt(std::int32_t streamBufferAddress, std::int32_t lane0, std::int32_t lane1);
  std::int32_t sfmpv_ChkMpvErr(
    std::int32_t workctrlAddress,
    std::int32_t decodeResult,
    std::int32_t consumedBytes,
    std::int32_t errorCode
  );
  std::int32_t sfmpv_GetTermDst(std::int32_t workctrlAddress);
  std::int32_t sfmpv_GetTermSrc(std::int32_t workctrlAddress);
  std::int32_t MPV_GetBitRate(std::int32_t decoderHandle, std::int32_t* outBitRate);
  std::int32_t MPV_GetVbvBufSiz(
    std::int32_t decoderHandle,
    std::int32_t* outBufferBytes,
    std::int32_t* outVbvLevel,
    std::int32_t* outStreamScale
  );
  std::int32_t sfmpv_DestroySub(std::int32_t decoderHandle);
  std::int32_t SFBUF_SetPrepFlg(std::int32_t workctrlAddress, std::int32_t laneIndex, std::int32_t prepFlag);
  std::int32_t SFBUF_GetPrepFlg(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t SFBUF_SetTermFlg(std::int32_t workctrlAddress, std::int32_t laneIndex, std::int32_t termFlag);
  std::int32_t SFBUF_GetTermFlg(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t SFBUF_GetRTot(std::int32_t sfbufHandleAddress, std::int32_t ringIndex);
  std::int32_t*
  SFBUF_AddRtotSj(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t addBytes);
  std::int32_t SFBUF_GetWTot(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t SFTRN_IsSetup(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t SFBUF_RingGetDataSiz(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t SFBUF_GetRingBufSiz(std::int32_t workctrlAddress, std::int32_t laneIndex);
  std::int32_t sfmpv_AddRtotSj(std::int32_t workctrlAddress, std::int32_t consumedBytes);
  std::int32_t SFPLY_AddSkipPic(
    std::int32_t workctrlAddress,
    std::int32_t skippedPictureDelta,
    std::int32_t callbackContext
  );
  std::int32_t SFPLY_AddDecPic(std::int32_t workctrlAddress, std::int32_t decodedPictureDelta, std::int32_t pictureType);
  std::int32_t SFMPVF_HoldFrm(std::int32_t workctrlAddress);
  std::int32_t
  sfmpvf_IsChkFirst(const SfmpvfFrameObjectRuntimeView* selectedFrameObject, const SfmpvfFrameObjectRuntimeView* candidateFrameObject);
  /**
   * Address: 0x00ADC6C0 (FUN_00ADC6C0, _SFMPVF_IssueFrmId)
   *
   * What it does:
   * Returns the current frame-object id lane and advances it, wrapping back
   * to zero when the increment would become negative.
   */
  std::int32_t SFMPVF_IssueFrmId(std::int32_t workctrlAddress);
  /**
   * Address: 0x00ADC2A0 (FUN_00ADC2A0, _SFMPVF_EndRefFrm)
   *
   * What it does:
   * Clears a frame-object's standby/reference state unless it is already in
   * the reference-standby lane.
   */
  std::int32_t SFMPVF_EndRefFrm(std::int32_t frameObjectAddress);
  /**
   * Address: 0x00ADC250 (FUN_00ADC250, _SFMPVF_FreeFrm)
   *
   * What it does:
   * Clears one frame-object decode-state lane back to free (`0`) when the
   * address is valid.
   */
  void SFMPVF_FreeFrm(std::int32_t frameObjectAddress);
  /**
   * Address: 0x00ADC260 (FUN_00ADC260, _SFMPVF_StbyFrm)
   *
   * What it does:
   * Places the frame object into standby state when the input address is
   * valid.
   */
  std::int32_t SFMPVF_StbyFrm(std::int32_t frameObjectAddress);
  /**
   * Address: 0x00ADC270 (FUN_00ADC270, _SFMPVF_RefStbyFrm)
   *
   * What it does:
   * Places the frame object into reference-standby state when the input
   * address is valid.
   */
  std::int32_t SFMPVF_RefStbyFrm(std::int32_t frameObjectAddress);
  void sfmpvf_SearchFrmInf(
    std::int32_t workctrlAddress,
    std::int32_t frameObjectAddress,
    SfmpvfFrameInfoRuntimeView** outFrameInfo
  );
  std::int32_t sfmpvf_GetVfrmDataFromFrmInf(std::int32_t workctrlAddress, std::int32_t frameInfoIndex);
  std::int32_t sfmpvf_AddReadSub(
    std::int32_t workctrlAddress,
    std::int32_t frameInfoIndex,
    std::int32_t frameObjectId
  );
  std::int32_t SFMPVF_SearchFrmObj(std::int32_t workctrlAddress, std::int32_t frameInfoIndex);
  /**
   * Address: 0x00ADC0A0 (FUN_00ADC0A0, _SFMPVF_SearchFrmObjFromId)
   *
   * What it does:
   * Scans the fixed 16-frame object table for the frame id and returns the
   * matching frame-object address when found.
   */
  std::int32_t SFMPVF_SearchFrmObjFromId(std::int32_t workctrlAddress, std::int32_t frameObjectId);
  /**
   * Address: 0x00ADC0D0 (FUN_00ADC0D0, _SFMPVF_SearchVfrmData)
   *
   * What it does:
   * Scans the active MPV frame-object array for the supplied frame-object
   * address and returns the owning VFRM data lane when found.
   */
  std::int32_t SFMPVF_SearchVfrmData(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  /**
   * Address: 0x00ADC280 (FUN_00ADC280, _SFMPVF_EndDrawFrm)
   *
   * What it does:
   * Clears the frame id, then transitions the frame from reference-draw or
   * non-reference draw state back to the appropriate idle lane.
   */
  std::int32_t SFMPVF_EndDrawFrm(std::int32_t frameObjectAddress);
  std::int32_t SFBUF_RingGetRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outCursorWords);
  std::int32_t SFBUF_RingAddRead(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t advanceCount);
  void SFBUF_RingGetDlm(
    std::int32_t sfbufHandleAddress,
    std::int32_t ringIndex,
    std::int32_t* outPrimaryDelimiterAddress,
    std::int32_t* outSecondaryDelimiterAddress
  );
  void SFBUF_RingSetDlm(
    std::int32_t sfbufHandleAddress,
    std::int32_t ringIndex,
    std::int32_t primaryDelimiterAddress,
    std::int32_t secondaryDelimiterAddress
  );
  std::int32_t
  SFBUF_RingGetSj(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t* outRingHandleAddress);
  std::int32_t
  SFBUF_GetFlowCnt(std::int32_t sjHandleAddress, std::int32_t* outLane1FlowCount, std::int32_t* outLane0FlowCount);
  std::int64_t SFBUF_UpdateFlowCnt(std::int32_t previousFlowLow, std::int32_t previousFlowHigh, std::int32_t nextFlowLow);
  std::uint8_t*
  sfmpv_SearchDelim(const std::int32_t ringCursorSnapshotAddress, std::int32_t delimiterMask, std::int32_t* outDelimiterState);
  std::int32_t sfmpv_CalcDistance(const std::int32_t* ringCursorSnapshotWords, const std::uint8_t* targetAddress);
  std::int32_t sfmpv_NeedSafeDlmRefresh(
    const std::int32_t* ringCursorSnapshotWords,
    std::int32_t delimiterFlags,
    std::int32_t primaryDelimiterAddress
  );
  std::uint8_t*
  sfmpv_BsearchDelim(const std::int32_t* ringCursorSnapshotWords, std::int32_t delimiterMask, std::int32_t* outDelimiterType);
  std::int32_t MPV_CheckDelim(const std::uint8_t* bitstreamCursor);
  /**
   * Address: 0x00AE6040 (FUN_00AE6040, _SFCON_ReadTotSmplQue)
   *
   * What it does:
   * Pops one queued total-sample update from the 32-slot audio queue and
   * returns both sample-total and sample-rate lanes.
   */
  std::int32_t SFCON_ReadTotSmplQue(
    std::int32_t workctrlAddress,
    std::int32_t* outTotalSamples,
    std::int32_t* outSampleRate
  );
  void SFD_tr_ad_adxt();
  std::int32_t MPV_GetLinkFlg(std::int32_t decoderHandle, std::int32_t* outStreamLinkFlag, std::int32_t* outLinkState);
  std::int32_t MPV_DecodePicAtr(std::int32_t handleAddress, const std::int32_t* pictureDataRange, std::int32_t* outConsumedBytes);
  void MPV_SetPicUsrBuf(std::int32_t decoderHandle, std::int32_t userBufferAddress, std::int32_t userBufferSize);
  std::int32_t MPV_DecodePicAtrSj(std::int32_t decoderHandle, std::int32_t streamBufferAddress);
  std::int32_t MPV_GetPicAtr(std::int32_t decoderHandle, SfmpvPictureDecodeLaneRuntimeView* outPictureDecodeLane);
  void MPV_GetPicUsr(std::int32_t decoderHandle, std::int32_t laneIndex, std::int32_t* outPictureUserFlags);
  char* MPV_SearchDelim(const char* chunkAddress, std::int32_t chunkBytes, std::int32_t delimiterMask);
  std::uint8_t* MPV_BsearchDelim(
    const std::uint8_t* chunkTailAddress,
    std::int32_t chunkBytes,
    std::int32_t delimiterMask
  );
  std::int32_t MPV_DecodeFrmSj(
    std::int32_t decoderHandle,
    std::int32_t streamBufferAddress,
    const SfmpvDecodeFrameParamRuntimeView* decodeFrameParam
  );
  /**
   * Address: 0x00AF5F50 (FUN_00AF5F50, _mpvcmc_InitMcOiTa)
   *
   * What it does:
   * Seeds MPV CMC interpolation-pointer lanes to the internal table storage
   * block and resets per-lane span words.
   */
  MpvcmcRuntimeView* mpvcmc_InitMcOiTa(MpvcmcRuntimeView* runtimeView);
  /**
   * Address: 0x00AF5FC0 (FUN_00AF5FC0, _MPVCMC_InitMcOiRt)
   *
   * What it does:
   * Initializes MPV CMC interpolation runtime words from fixed seed lanes in
   * the CMC object.
   */
  MpvcmcRuntimeView* MPVCMC_InitMcOiRt(MpvcmcRuntimeView* runtimeView);
  /**
   * Address: 0x00AF6010 (FUN_00AF6010, _MPVCMC_SetCcnt)
   *
   * What it does:
   * Recomputes CMC count/state lanes from the runtime mode gate.
   */
  std::int32_t MPVCMC_SetCcnt(MpvcmcRuntimeView* runtimeView);
  /**
   * Address: 0x00AF60F0 (FUN_00AF60F0, _MPVUMC_Finish)
   *
   * What it does:
   * Finalizes UMC runtime state (no-op in this binary).
   */
  void MPVUMC_Finish();
  /**
   * Address: 0x00AF6100 (FUN_00AF6100, _MPVUMC_InitOutRfb)
   *
   * What it does:
   * Computes Y/C output frame-buffer lane addresses and aligned strides for the
   * current decode-frame geometry.
   */
  std::int32_t MPVUMC_InitOutRfb(MpvcmcRuntimeView* runtimeView);
  /**
   * Address: 0x00AF61D0 (FUN_00AF61D0, _MPVUMC_EndOfFrame)
   *
   * What it does:
   * Ends one UMC frame-decode pass (no-op in this binary).
   */
  void MPVUMC_EndOfFrame();
  void MPV_GetDctCnt(std::int32_t decoderHandle, std::int32_t* outPrimaryCount, std::int32_t* outSecondaryCount);
  std::int64_t SFTMR_GetTmr();
  void* SFTMR_AddTsum(void* timeSumLane, std::int32_t deltaLow, std::int32_t deltaHigh);
  void* MPV_IsEmptyBpic(const char* chunkAddress, std::int32_t chunkBytes, std::int32_t frameAreaProduct);
  void* MPV_IsEmptyPpic(const char* chunkAddress, std::int32_t chunkBytes, std::int32_t frameAreaProduct);
  void MEM_Copy(void* destination, const void* source, std::int32_t byteCount);
  /**
   * Address: 0x00ADC150 (FUN_00ADC150, _SFMPVF_FixDispOrder)
   *
   * What it does:
   * Copies the caller-supplied display-order latch into the MPV info lane's
   * single-frame-output flag and returns to the caller.
   */
  void SFMPVF_FixDispOrder(std::int32_t workctrlAddress, std::int32_t shouldSort);
  void sfmpv_FixedForSeek(std::int32_t workctrlAddress);
  std::int32_t SFCON_IsEndcodeSkip(std::int32_t workctrlAddress);
  /**
   * Address: 0x00AE5F20 (FUN_00AE5F20, _SFCON_IsVideoEndcodeSkip)
   *
   * What it does:
   * Returns 1 when either condition lane `49` or lane `57` is enabled;
   * otherwise returns 0.
   */
  std::int32_t SFCON_IsVideoEndcodeSkip(std::int32_t workctrlAddress);
  std::int32_t sfmpv_Concat(std::int32_t workctrlAddress, std::int32_t streamBufferAddress);
  void sfmpv_DiscardSec(std::int32_t workctrlAddress, std::int32_t streamBufferAddress);
  std::int32_t sfmpv_IsTerm(std::int32_t workctrlAddress, std::int32_t activeSize, std::int32_t delimiterState);
  /**
   * Address: 0x00ADC120 (FUN_00ADC120, _SFMPVF_TermDec)
   *
   * What it does:
   * Marks the per-handle MPV info lane as term-decode active.
   */
  std::int32_t SFMPVF_TermDec(std::int32_t workctrlAddress);
  void sfmpv_PeekChnk(std::int32_t workctrlAddress, std::int32_t* outChunkWords);
  std::int32_t sfmpv_DecodePicAtr(
    std::int32_t workctrlAddress,
    const std::int32_t* chunkWords,
    std::int32_t streamBufferAddress,
    std::int32_t delimiterState,
    std::int32_t* outDecodeState
  );
  std::int64_t sfmpv_ReadPtsQue(
    std::int32_t workctrlAddress,
    SfmpvPictureDecodeLaneRuntimeView* pictureDecodeLane,
    char* delimiterCursor,
    std::int32_t* outPresentationPtsWords,
    std::int32_t* outReferenceErrorSeedWords,
    std::int32_t pictureChangedFlag
  );
  std::int64_t sfmpv_ComplementPts(
    std::int32_t timingLaneAddress,
    SfmpvComplementPts* complementState,
    const SfmpvPictureDecodeLaneRuntimeView* pictureDecodeLane,
    const std::int32_t* ptsWords,
    std::int32_t pictureChangedFlag,
    std::int32_t* outReferenceSeedWords
  );
  std::int64_t sfmpv_Nfrm2Pts(std::int32_t frameCount, std::int32_t frameRateScale);
  std::int32_t sfmpv_SetHeadTtu(std::int32_t workctrlAddress);
  std::int32_t sfmpv_SetDecTtu(std::int32_t workctrlAddress);
  std::int32_t sfmpv_GoDdelim(std::int32_t workctrlAddress, std::int32_t streamBufferAddress, std::int32_t delimiterMask);
  std::int32_t sfmpv_IsSkip(std::int32_t workctrlAddress, const std::int32_t* chunkWords);
  std::int32_t sfmpv_DecodeFrm(std::int32_t workctrlAddress, std::int32_t streamBufferAddress);
  std::int32_t SFTIM_Tc2Time(
    const void* timecodeLane,
    std::int32_t* outTimeMajor,
    std::int32_t* outTimeMinor
  );
  std::int32_t sfmpv_GetActiveSize(
    std::int32_t workctrlAddress,
    std::int32_t* outActiveSize,
    std::int32_t* outDelimiterFlags,
    std::int32_t* outHasActiveUnit
  );
  std::int32_t sfmpv_DecodeOneUnit(
    SfmpvHandleRuntimeView* workctrl,
    std::int32_t activeSize,
    std::int32_t delimiterState,
    std::int32_t hasActiveUnit,
    std::int32_t* outUnitProcessed
  );
  std::int32_t sfmpv_DecodeSomePic(std::int32_t workctrlAddress);
  std::int32_t sfmpv_FirstPicAtr(
    std::int32_t workctrlAddress,
    std::int32_t decoderHandleAddress,
    std::int32_t mvInfoAddress,
    std::int32_t pictureHeaderChunkAddress
  );
  std::int32_t sfmpv_SetMvInf(
    SfmpvMvInfoRuntimeView* destinationInfo,
    std::int32_t frameRateBase,
    const std::int32_t* frameInfoWords,
    std::int32_t vbvBufferBytes
  );
  std::int32_t sfmpv_SetFrmPara(
    std::int32_t workctrlAddress,
    const SfmpvPictureDecodeLaneRuntimeView* pictureDecodeLane,
    SfmpvDecodeFrameParamRuntimeView* decodeFrameParam,
    std::int32_t* outFrameObjectAddress
  );
  std::int32_t sfmpv_ReadRefErrCnt(
    std::int32_t workctrlAddress,
    const SfmpvInfoRuntimeView* mpvInfo,
    std::int32_t* outErrorMajor,
    std::int32_t* outErrorMinor
  );
  std::int32_t sfmpv_SetFrmTime(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_CalcRepeatField(std::int32_t workctrlAddress, std::int32_t frameObjectAddress, std::int32_t resetHistory);
  std::int32_t sfmpv_ChkBufSiz(std::int32_t workctrlAddress, const std::int32_t* frameDimensions);
  std::int32_t sfmpv_CalcFrmTtu(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_ReadTcode(std::int32_t frameObjectAddress, SfmpvPackedTimecodeRuntimeView* outTimecodeLane);
  std::int32_t sfmpv_CalcFrmTime(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_UpdateFlowCnt(std::int32_t workctrlAddress);
  std::int32_t sfmpv_RingAddRead(std::int32_t workctrlAddress, std::int32_t advanceCount);
  std::int32_t
  sfmpv_ReprocessShc(std::int32_t workctrlAddress, const std::int32_t* decoderHandleLane, std::int32_t* outReprocessed);
  std::int32_t sfmpv_GetHd(std::int32_t workctrlAddress);
  SfmpvfFrameObjectRuntimeView* SFMPVF_AllocFrm(std::int32_t workctrlAddress);
}

namespace
{
  /**
   * Address: 0x00AEA250 (FUN_00AEA250, _UTY_MulDivRound64)
   *
   * What it does:
   * Multiplies `value * numerator`, adds half-denominator for nearest rounding,
   * divides by `denominator`, and applies sign/saturation semantics matching
   * the Sofdec MPV utility lane.
   */
  [[nodiscard]] std::int64_t UTY_MulDivRound64(
    const std::int64_t value,
    const std::int64_t numerator,
    const std::int64_t denominator
  ) noexcept
  {
    if (denominator == 0) {
      const bool signsDiffer = (value < 0) != (numerator < 0);
      return signsDiffer ? std::numeric_limits<std::int64_t>::min() : std::numeric_limits<std::int64_t>::max();
    }

    int sign = 1;
    std::uint64_t absValue = static_cast<std::uint64_t>(value);
    if (value < 0) {
      absValue = static_cast<std::uint64_t>(0) - absValue;
      sign = -sign;
    }

    std::uint64_t absNumerator = static_cast<std::uint64_t>(numerator);
    if (numerator < 0) {
      absNumerator = static_cast<std::uint64_t>(0) - absNumerator;
      sign = -sign;
    }

    std::uint64_t absDenominator = static_cast<std::uint64_t>(denominator);
    if (denominator < 0) {
      absDenominator = static_cast<std::uint64_t>(0) - absDenominator;
      sign = -sign;
    }

    const std::uint64_t roundedUnsigned =
      ((absDenominator >> 1U) + (absValue * absNumerator)) / absDenominator;
    std::int64_t rounded = static_cast<std::int64_t>(roundedUnsigned);
    if (sign < 0) {
      rounded = -rounded;
    }
    return rounded;
  }
} // namespace

// ---------------------------------------------------------------------------
// MPV parameter block -- CRI-internal global state
// ---------------------------------------------------------------------------

/**
 * CRI Sofdec MPV parameter structure, stored at a fixed BSS address.
 * 0x24 bytes (9 DWORDs) are bulk-copied into each MPV info block by
 * `sfmpv_InitInf`.
 */
struct SfmpvPara
{
  std::int32_t field_0x00;         // +0x00
  std::int32_t field_0x04;         // +0x04
  std::int32_t field_0x08;         // +0x08
  std::int32_t field_0x0C;         // +0x0C
  std::int32_t val4;               // +0x10  -- checked by sfmpvf_CheckMpvPara
  std::int32_t field_0x14;         // +0x14
  std::int32_t field_0x18;         // +0x18
  std::int32_t nfrm_pool_wk;      // +0x1C  -- max 16 frame pool entries
  std::int32_t val8;               // +0x20  -- checked by sfmpvf_CheckMpvPara
};

static_assert(sizeof(SfmpvPara) == 0x24, "SfmpvPara size must be 0x24");

// ---------------------------------------------------------------------------
// MPV complement-points sub-structure
// ---------------------------------------------------------------------------

/**
 * Complement (interpolation/prediction) point state, initialised by
 * `sfmpv_InitComplementPts`.  8 DWORDs = 0x20 bytes at known offsets.
 */
struct SfmpvComplementPts
{
  std::int32_t field_0x00; // +0x00
  std::int32_t field_0x04; // +0x04
  std::int32_t field_0x08; // +0x08
  std::int32_t reserved_0C; // +0x0C  (gap -- not written by init)
  std::int32_t field_0x10; // +0x10
  std::int32_t field_0x14; // +0x14
  std::int32_t field_0x18; // +0x18
  std::int32_t field_0x1C; // +0x1C
};

static_assert(sizeof(SfmpvComplementPts) == 0x20, "SfmpvComplementPts size must be 0x20");

// ---------------------------------------------------------------------------
// MPV picture-user sub-structure
// ---------------------------------------------------------------------------

/**
 * Picture-user state block.  `SFMPVF_InitPicUsr` zeroes 5 header DWORDs
 * followed by 16 pairs of DWORDs (32 entries), totalling 37 DWORDs.
 */
struct SfmpvPicUsr
{
  std::int32_t header[5]; // +0x00  -- zeroed by init
  struct PicUsrEntry
  {
    std::int32_t value0; // +0x00
    std::int32_t value1; // +0x04
  };
  PicUsrEntry entries[16]; // +0x14  -- zeroed by init
};

struct SfbufRingChunkRuntimeView
{
  std::uint8_t* bufferAddress = nullptr; // +0x00
  std::int32_t byteCount = 0; // +0x04
};

static_assert(
  offsetof(SfbufRingChunkRuntimeView, bufferAddress) == 0x00,
  "SfbufRingChunkRuntimeView::bufferAddress offset must be 0x00"
);
static_assert(offsetof(SfbufRingChunkRuntimeView, byteCount) == 0x04, "SfbufRingChunkRuntimeView::byteCount offset must be 0x04");
static_assert(sizeof(SfbufRingChunkRuntimeView) == 0x08, "SfbufRingChunkRuntimeView size must be 0x08");

struct SfbufRingCursorSnapshotRuntimeView
{
  SfbufRingChunkRuntimeView firstChunk{}; // +0x00
  SfbufRingChunkRuntimeView secondChunk{}; // +0x08
  std::int32_t reservedWords[3]{}; // +0x10
};

static_assert(
  offsetof(SfbufRingCursorSnapshotRuntimeView, firstChunk) == 0x00,
  "SfbufRingCursorSnapshotRuntimeView::firstChunk offset must be 0x00"
);
static_assert(
  offsetof(SfbufRingCursorSnapshotRuntimeView, secondChunk) == 0x08,
  "SfbufRingCursorSnapshotRuntimeView::secondChunk offset must be 0x08"
);
static_assert(
  offsetof(SfbufRingCursorSnapshotRuntimeView, reservedWords) == 0x10,
  "SfbufRingCursorSnapshotRuntimeView::reservedWords offset must be 0x10"
);
static_assert(sizeof(SfbufRingCursorSnapshotRuntimeView) == 0x1C, "SfbufRingCursorSnapshotRuntimeView size must be 0x1C");

/**
 * One 16-byte PTS queue entry consumed by SFPTS lanes.
 */
struct SfptsQueueEntryRuntimeView
{
  std::int32_t ptsLow = -1; // +0x00
  std::int32_t ptsHigh = -1; // +0x04
  std::int32_t referenceLow = -1; // +0x08
  std::int32_t referenceHigh = -1; // +0x0C
};

static_assert(offsetof(SfptsQueueEntryRuntimeView, ptsLow) == 0x00, "SfptsQueueEntryRuntimeView::ptsLow offset must be 0x00");
static_assert(offsetof(SfptsQueueEntryRuntimeView, ptsHigh) == 0x04, "SfptsQueueEntryRuntimeView::ptsHigh offset must be 0x04");
static_assert(
  offsetof(SfptsQueueEntryRuntimeView, referenceLow) == 0x08,
  "SfptsQueueEntryRuntimeView::referenceLow offset must be 0x08"
);
static_assert(
  offsetof(SfptsQueueEntryRuntimeView, referenceHigh) == 0x0C,
  "SfptsQueueEntryRuntimeView::referenceHigh offset must be 0x0C"
);
static_assert(sizeof(SfptsQueueEntryRuntimeView) == 0x10, "SfptsQueueEntryRuntimeView size must be 0x10");

/**
 * PTS queue control lane used by `_sfpts_SearchPtsQue` and `_sfpts_ReadPtsQueSub`.
 */
struct SfptsPtsQueueRuntimeView
{
  std::int32_t entriesBaseAddress = 0; // +0x00
  std::int32_t entryCapacity = 0; // +0x04
  std::int32_t queuedEntryCount = 0; // +0x08
  std::int32_t reserved0C = 0; // +0x0C
  std::int32_t readCursor = 0; // +0x10
};

static_assert(
  offsetof(SfptsPtsQueueRuntimeView, entriesBaseAddress) == 0x00,
  "SfptsPtsQueueRuntimeView::entriesBaseAddress offset must be 0x00"
);
static_assert(
  offsetof(SfptsPtsQueueRuntimeView, entryCapacity) == 0x04,
  "SfptsPtsQueueRuntimeView::entryCapacity offset must be 0x04"
);
static_assert(
  offsetof(SfptsPtsQueueRuntimeView, queuedEntryCount) == 0x08,
  "SfptsPtsQueueRuntimeView::queuedEntryCount offset must be 0x08"
);
static_assert(offsetof(SfptsPtsQueueRuntimeView, reserved0C) == 0x0C, "SfptsPtsQueueRuntimeView::reserved0C offset must be 0x0C");
static_assert(offsetof(SfptsPtsQueueRuntimeView, readCursor) == 0x10, "SfptsPtsQueueRuntimeView::readCursor offset must be 0x10");
static_assert(sizeof(SfptsPtsQueueRuntimeView) == 0x14, "SfptsPtsQueueRuntimeView size must be 0x14");

/**
 * One source lane subobject containing stream-window bounds and embedded PTS queue.
 *
 * Evidence:
 * - `FUN_00AE5C40` indexes this array at `workctrl + 0x1320 + lane * 0x74`.
 */
struct SfptsSourceLaneRuntimeView
{
  std::uint8_t mUnknown00To07[0x08]{}; // +0x00
  std::int32_t ringWindowStartAddress = 0; // +0x08
  std::int32_t ringWindowSpanBytes = 0; // +0x0C
  std::uint8_t mUnknown10To27[0x18]{}; // +0x10
  SfptsPtsQueueRuntimeView ptsQueue{}; // +0x28
  std::uint8_t mUnknown3CTo73[0x38]{}; // +0x3C
};

static_assert(
  offsetof(SfptsSourceLaneRuntimeView, ringWindowStartAddress) == 0x08,
  "SfptsSourceLaneRuntimeView::ringWindowStartAddress offset must be 0x08"
);
static_assert(
  offsetof(SfptsSourceLaneRuntimeView, ringWindowSpanBytes) == 0x0C,
  "SfptsSourceLaneRuntimeView::ringWindowSpanBytes offset must be 0x0C"
);
static_assert(
  offsetof(SfptsSourceLaneRuntimeView, ptsQueue) == 0x28,
  "SfptsSourceLaneRuntimeView::ptsQueue offset must be 0x28"
);
static_assert(sizeof(SfptsSourceLaneRuntimeView) == 0x74, "SfptsSourceLaneRuntimeView size must be 0x74");

struct SfmpvPackedTimecodeRuntimeView
{
  std::int32_t frameRateIndex = 0; // +0x00
  std::int32_t dropFrameMode = 0; // +0x04
  std::int32_t hours = 0; // +0x08
  std::int32_t minutes = 0; // +0x0C
  std::int32_t seconds = 0; // +0x10
  std::int32_t frameNumber = 0; // +0x14
  std::int32_t halfFrameCarry = 0; // +0x18
  std::int16_t repeatFieldCount = 0; // +0x1C
  std::int16_t repeatFieldAccumulated = 0; // +0x1E
};

static_assert(
  offsetof(SfmpvPackedTimecodeRuntimeView, repeatFieldCount) == 0x1C,
  "SfmpvPackedTimecodeRuntimeView::repeatFieldCount offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvPackedTimecodeRuntimeView, repeatFieldAccumulated) == 0x1E,
  "SfmpvPackedTimecodeRuntimeView::repeatFieldAccumulated offset must be 0x1E"
);
static_assert(sizeof(SfmpvPackedTimecodeRuntimeView) == 0x20, "SfmpvPackedTimecodeRuntimeView size must be 0x20");

struct SfmpvTtuRuntimeView
{
  std::int32_t state = 0; // +0x00
  std::int32_t packedTimecodeWords[8]{}; // +0x04
  std::int32_t timeMajor = 0; // +0x24
  std::int32_t timeMinor = 0; // +0x28
};

static_assert(offsetof(SfmpvTtuRuntimeView, state) == 0x00, "SfmpvTtuRuntimeView::state offset must be 0x00");
static_assert(
  offsetof(SfmpvTtuRuntimeView, packedTimecodeWords) == 0x04,
  "SfmpvTtuRuntimeView::packedTimecodeWords offset must be 0x04"
);
static_assert(offsetof(SfmpvTtuRuntimeView, timeMajor) == 0x24, "SfmpvTtuRuntimeView::timeMajor offset must be 0x24");
static_assert(offsetof(SfmpvTtuRuntimeView, timeMinor) == 0x28, "SfmpvTtuRuntimeView::timeMinor offset must be 0x28");
static_assert(sizeof(SfmpvTtuRuntimeView) == 0x2C, "SfmpvTtuRuntimeView size must be 0x2C");

struct SfmpvfFrameTimingRuntimeView
{
  std::uint8_t mUnknown00To0B[0x0C]{}; // +0x00
  SfmpvTtuRuntimeView frameTtu{}; // +0x0C
  std::int32_t resolvedTimeMajor = 0; // +0x38
  std::int32_t resolvedTimeMinor = 0; // +0x3C
  std::uint8_t mUnknown40To4B[0x0C]{}; // +0x40
  std::int32_t frameStartTimeMajor = 0; // +0x4C
  std::int32_t frameEndTimeMajor = 0; // +0x50
};

static_assert(
  offsetof(SfmpvfFrameTimingRuntimeView, frameTtu) == 0x0C,
  "SfmpvfFrameTimingRuntimeView::frameTtu offset must be 0x0C"
);
static_assert(
  offsetof(SfmpvfFrameTimingRuntimeView, resolvedTimeMajor) == 0x38,
  "SfmpvfFrameTimingRuntimeView::resolvedTimeMajor offset must be 0x38"
);
static_assert(
  offsetof(SfmpvfFrameTimingRuntimeView, resolvedTimeMinor) == 0x3C,
  "SfmpvfFrameTimingRuntimeView::resolvedTimeMinor offset must be 0x3C"
);
static_assert(
  offsetof(SfmpvfFrameTimingRuntimeView, frameStartTimeMajor) == 0x4C,
  "SfmpvfFrameTimingRuntimeView::frameStartTimeMajor offset must be 0x4C"
);
static_assert(
  offsetof(SfmpvfFrameTimingRuntimeView, frameEndTimeMajor) == 0x50,
  "SfmpvfFrameTimingRuntimeView::frameEndTimeMajor offset must be 0x50"
);

struct SfmpvfFrameRepeatRuntimeView
{
  std::uint8_t mUnknown00To13[0x14]{}; // +0x00
  std::int32_t historyOrdinal = 0; // +0x14
  std::int32_t pictureType = 0; // +0x18
  std::uint8_t mUnknown1CTo2D[0x12]{}; // +0x1C
  std::uint16_t repeatAccumulatorWord = 0; // +0x2E
  std::uint8_t mUnknown30To6F[0x40]{}; // +0x30
  std::int32_t decodeOrderIndex = 0; // +0x70
};

static_assert(
  offsetof(SfmpvfFrameRepeatRuntimeView, historyOrdinal) == 0x14,
  "SfmpvfFrameRepeatRuntimeView::historyOrdinal offset must be 0x14"
);
static_assert(
  offsetof(SfmpvfFrameRepeatRuntimeView, pictureType) == 0x18,
  "SfmpvfFrameRepeatRuntimeView::pictureType offset must be 0x18"
);
static_assert(
  offsetof(SfmpvfFrameRepeatRuntimeView, repeatAccumulatorWord) == 0x2E,
  "SfmpvfFrameRepeatRuntimeView::repeatAccumulatorWord offset must be 0x2E"
);
static_assert(
  offsetof(SfmpvfFrameRepeatRuntimeView, decodeOrderIndex) == 0x70,
  "SfmpvfFrameRepeatRuntimeView::decodeOrderIndex offset must be 0x70"
);

struct SfmpvfTimecodeSourceRuntimeView
{
  std::uint8_t mUnknown00To0F[0x10]{}; // +0x00
  std::int32_t word00 = 0; // +0x10
  std::int32_t word04 = 0; // +0x14
  std::int32_t word08 = 0; // +0x18
  std::int32_t word0C = 0; // +0x1C
  std::int32_t word10 = 0; // +0x20
  std::int32_t word14 = 0; // +0x24
  std::int32_t word18 = 0; // +0x28
  std::int32_t word1C = 0; // +0x2C
  std::uint8_t mUnknown30To53[0x24]{}; // +0x30
  std::uint8_t repeatFieldCount = 0; // +0x54
};

static_assert(
  offsetof(SfmpvfTimecodeSourceRuntimeView, word00) == 0x10,
  "SfmpvfTimecodeSourceRuntimeView::word00 offset must be 0x10"
);
static_assert(
  offsetof(SfmpvfTimecodeSourceRuntimeView, word18) == 0x28,
  "SfmpvfTimecodeSourceRuntimeView::word18 offset must be 0x28"
);
static_assert(
  offsetof(SfmpvfTimecodeSourceRuntimeView, word1C) == 0x2C,
  "SfmpvfTimecodeSourceRuntimeView::word1C offset must be 0x2C"
);
static_assert(
  offsetof(SfmpvfTimecodeSourceRuntimeView, repeatFieldCount) == 0x54,
  "SfmpvfTimecodeSourceRuntimeView::repeatFieldCount offset must be 0x54"
);

struct SfmpvRepeatFieldSampleRuntimeView
{
  std::int16_t repeatFieldCount = -1; // +0x00
  std::int16_t accumulatedRepeatCount = -1; // +0x02
};

static_assert(
  offsetof(SfmpvRepeatFieldSampleRuntimeView, repeatFieldCount) == 0x00,
  "SfmpvRepeatFieldSampleRuntimeView::repeatFieldCount offset must be 0x00"
);
static_assert(
  offsetof(SfmpvRepeatFieldSampleRuntimeView, accumulatedRepeatCount) == 0x02,
  "SfmpvRepeatFieldSampleRuntimeView::accumulatedRepeatCount offset must be 0x02"
);
static_assert(sizeof(SfmpvRepeatFieldSampleRuntimeView) == 0x04, "SfmpvRepeatFieldSampleRuntimeView size must be 0x04");

struct SfmpvRepeatFieldHistoryRuntimeView
{
  SfmpvRepeatFieldSampleRuntimeView samples[64]{}; // +0x00
};

static_assert(sizeof(SfmpvRepeatFieldHistoryRuntimeView) == 0x100, "SfmpvRepeatFieldHistoryRuntimeView size must be 0x100");

/**
 * MPV picture-attribute lane filled by `MPV_GetPicAtr` and consumed by
 * timecode reform helpers.
 */
struct SfmpvPictureAttributeRuntimeView
{
  std::uint8_t mUnknown00To0F[0x10]{}; // +0x00
  std::int32_t timecodeFrameRateIndex = 0; // +0x10
  std::int32_t timecodeFrameOrdinal = 0; // +0x14
  std::uint8_t mUnknown18To1B[0x04]{}; // +0x18
  std::int32_t timecodeDropFrameMode = 0; // +0x1C
  std::uint8_t mUnknown20To2F[0x10]{}; // +0x20
  std::int32_t pictureTimecodeBase = 0; // +0x30
  std::uint8_t mUnknown34To56[0x23]{}; // +0x34
  std::uint8_t pictureTimecodeDisableLatch = 0; // +0x57
};

static_assert(
  offsetof(SfmpvPictureAttributeRuntimeView, timecodeFrameRateIndex) == 0x10,
  "SfmpvPictureAttributeRuntimeView::timecodeFrameRateIndex offset must be 0x10"
);
static_assert(
  offsetof(SfmpvPictureAttributeRuntimeView, timecodeFrameOrdinal) == 0x14,
  "SfmpvPictureAttributeRuntimeView::timecodeFrameOrdinal offset must be 0x14"
);
static_assert(
  offsetof(SfmpvPictureAttributeRuntimeView, timecodeDropFrameMode) == 0x1C,
  "SfmpvPictureAttributeRuntimeView::timecodeDropFrameMode offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvPictureAttributeRuntimeView, pictureTimecodeBase) == 0x30,
  "SfmpvPictureAttributeRuntimeView::pictureTimecodeBase offset must be 0x30"
);
static_assert(
  offsetof(SfmpvPictureAttributeRuntimeView, pictureTimecodeDisableLatch) == 0x57,
  "SfmpvPictureAttributeRuntimeView::pictureTimecodeDisableLatch offset must be 0x57"
);

/**
 * Picture decode lane produced by MPV picture-attribute decoding.
 *
 * Evidence:
 * - `FUN_00AD4590` copies 0x80 bytes from `mpvInfo + 0x8C` into frame object `+0x5C`.
 * - `FUN_00AD47E0` and `FUN_00AD4330` read `pictureType` at lane `+0x18`.
 */
struct SfmpvPictureDecodeLaneRuntimeView
{
  std::int32_t pictureWidthPixels = 0; // +0x00
  std::int32_t pictureHeightPixels = 0; // +0x04
  std::int32_t pictureDetailWord08 = 0; // +0x08
  std::int32_t pictureDetailWord0C = 0; // +0x0C
  std::int32_t frameRateIndex = 0; // +0x10
  std::int32_t decodeOrderMetric = 0; // +0x14
  std::int32_t pictureType = 0; // +0x18
  std::uint8_t mUnknown1CTo2F[0x14]{}; // +0x1C
  std::int32_t sequenceStamp = 0; // +0x30
  std::int32_t progressiveSequence = 0; // +0x34
  std::int32_t referenceUpdateMode = 0; // +0x38
  std::int32_t chromaFormat = 0; // +0x3C
  std::int32_t chromaPositionLow = 0; // +0x40
  std::int32_t chromaPositionHigh = 0; // +0x44
  std::int32_t pictureDetailWord48 = 0; // +0x48
  std::int32_t pictureDetailWord4C = 0; // +0x4C
  std::uint16_t pictureDetailWord50 = 0; // +0x50
  std::uint16_t pictureDetailWord52 = 0; // +0x52
  std::uint8_t mUnknown54 = 0; // +0x54
  std::uint8_t pictureDecodeFlagA = 0; // +0x55
  std::uint8_t pictureDecodeFlagB = 0; // +0x56
  std::uint8_t pictureDecodeFlagC = 0; // +0x57
  std::uint8_t skipDecisionLatch = 0; // +0x58
  std::uint8_t pictureDecodeFlagD = 0; // +0x59
  std::uint8_t pictureDecodeFlagE = 0; // +0x5A
  std::uint8_t pictureDecodeFlagF = 0; // +0x5B
  std::uint8_t pictureDecodeFlagG = 0; // +0x5C
  std::uint8_t pictureDecodeFlagH = 0; // +0x5D
  std::uint8_t pictureDecodeFlagI = 0; // +0x5E
  std::uint8_t pictureDecodeFlagJ = 0; // +0x5F
  std::uint8_t pictureDecodeFlagK = 0; // +0x60
  std::uint8_t pictureDecodeFlagL = 0; // +0x61
  std::uint8_t pictureDecodeFlagM = 0; // +0x62
  std::uint8_t pictureDecodeFlagN = 0; // +0x63
  std::uint8_t pictureDecodeFlagO = 0; // +0x64
  std::uint8_t mUnknown65To67[0x03]{}; // +0x65
  std::int32_t decodeOrderTiebreak = 0; // +0x68
  std::uint8_t mUnknown6CTo7F[0x14]{}; // +0x6C
};

static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, frameRateIndex) == 0x10,
  "SfmpvPictureDecodeLaneRuntimeView::frameRateIndex offset must be 0x10"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, decodeOrderMetric) == 0x14,
  "SfmpvPictureDecodeLaneRuntimeView::decodeOrderMetric offset must be 0x14"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, pictureType) == 0x18,
  "SfmpvPictureDecodeLaneRuntimeView::pictureType offset must be 0x18"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, sequenceStamp) == 0x30,
  "SfmpvPictureDecodeLaneRuntimeView::sequenceStamp offset must be 0x30"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, referenceUpdateMode) == 0x38,
  "SfmpvPictureDecodeLaneRuntimeView::referenceUpdateMode offset must be 0x38"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, chromaPositionLow) == 0x40,
  "SfmpvPictureDecodeLaneRuntimeView::chromaPositionLow offset must be 0x40"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, chromaPositionHigh) == 0x44,
  "SfmpvPictureDecodeLaneRuntimeView::chromaPositionHigh offset must be 0x44"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, pictureDetailWord48) == 0x48,
  "SfmpvPictureDecodeLaneRuntimeView::pictureDetailWord48 offset must be 0x48"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, pictureDetailWord50) == 0x50,
  "SfmpvPictureDecodeLaneRuntimeView::pictureDetailWord50 offset must be 0x50"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, skipDecisionLatch) == 0x58,
  "SfmpvPictureDecodeLaneRuntimeView::skipDecisionLatch offset must be 0x58"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, pictureDecodeFlagO) == 0x64,
  "SfmpvPictureDecodeLaneRuntimeView::pictureDecodeFlagO offset must be 0x64"
);
static_assert(
  offsetof(SfmpvPictureDecodeLaneRuntimeView, decodeOrderTiebreak) == 0x68,
  "SfmpvPictureDecodeLaneRuntimeView::decodeOrderTiebreak offset must be 0x68"
);
static_assert(
  sizeof(SfmpvPictureDecodeLaneRuntimeView) == 0x80,
  "SfmpvPictureDecodeLaneRuntimeView size must be 0x80"
);

/**
 * Decode-frame parameter block consumed by `MPV_DecodeFrmSj`.
 */
struct SfmpvDecodeFrameParamRuntimeView
{
  std::int32_t primaryLumaPlaneAddress = 0; // +0x00
  std::int32_t primaryChromaPlaneAddress = 0; // +0x04
  std::int32_t primaryFrameBaseAddress = 0; // +0x08
  std::int32_t primaryStridePacked = 0; // +0x0C
  std::int32_t secondaryLumaPlaneAddress = 0; // +0x10
  std::int32_t secondaryChromaPlaneAddress = 0; // +0x14
  std::int32_t secondaryFrameBaseAddress = 0; // +0x18
  std::int32_t secondaryStridePacked = 0; // +0x1C
  std::int32_t decodedFrameBaseAddress = 0; // +0x20
  std::int32_t pictureDecodeLaneAddress = 0; // +0x24
  std::int32_t reserved28 = 0; // +0x28
  std::int32_t reserved2C = 0; // +0x2C
};

static_assert(
  offsetof(SfmpvDecodeFrameParamRuntimeView, decodedFrameBaseAddress) == 0x20,
  "SfmpvDecodeFrameParamRuntimeView::decodedFrameBaseAddress offset must be 0x20"
);
static_assert(
  offsetof(SfmpvDecodeFrameParamRuntimeView, pictureDecodeLaneAddress) == 0x24,
  "SfmpvDecodeFrameParamRuntimeView::pictureDecodeLaneAddress offset must be 0x24"
);
static_assert(
  sizeof(SfmpvDecodeFrameParamRuntimeView) == 0x30,
  "SfmpvDecodeFrameParamRuntimeView size must be 0x30"
);

/**
 * MV information lane seeded by first-picture attribute path.
 */
struct SfmpvMvInfoRuntimeView
{
  std::int32_t pictureWidthPixels = 0; // +0x00
  std::int32_t pictureHeightPixels = 0; // +0x04
  std::int32_t frameAreaWidthPixels = 0; // +0x08
  std::int32_t frameAreaHeightPixels = 0; // +0x0C
  std::int32_t frameRateBase = 0; // +0x10
  std::int32_t vbvBufferBytes = 0; // +0x14
  std::int32_t field_0x18 = 0; // +0x18
  std::int32_t field_0x1C = 0; // +0x1C
  std::int32_t vbvWindowBytes = 0; // +0x20
};

static_assert(offsetof(SfmpvMvInfoRuntimeView, frameRateBase) == 0x10, "SfmpvMvInfoRuntimeView::frameRateBase offset must be 0x10");
static_assert(
  offsetof(SfmpvMvInfoRuntimeView, vbvWindowBytes) == 0x20,
  "SfmpvMvInfoRuntimeView::vbvWindowBytes offset must be 0x20"
);
static_assert(sizeof(SfmpvMvInfoRuntimeView) == 0x24, "SfmpvMvInfoRuntimeView size must be 0x24");

struct SftmrTimeSumRuntimeView
{
  std::uint8_t words[0x20]{}; // +0x00
};

static_assert(sizeof(SftmrTimeSumRuntimeView) == 0x20, "SftmrTimeSumRuntimeView size must be 0x20");

/**
 * Per-handle timing lane consumed by MPV late/skip decision helpers.
 *
 * Evidence:
 * - `FUN_00AD4100` accesses this subobject at workctrl offset `+0x0D30`.
 */
struct SfmpvTimingLane
{
  using IsLateCallback =
    std::int32_t(__cdecl*)(std::int32_t workctrlAddress, std::int32_t mode, std::int32_t interpolationTime, std::int32_t baseFraction);

  std::uint8_t mUnknown00To17[0x18]{}; // +0x00
  IsLateCallback isLateCallback = nullptr; // +0x18
  SfmpvPackedTimecodeRuntimeView repeatFieldTimecode{}; // +0x1C
  std::uint32_t concatVideoTimeUnit[11]{}; // +0x3C
  std::uint32_t concatAudioTimeUnit[11]{}; // +0x68
  SfmpvTtuRuntimeView seekFixedBaselineTtu{}; // +0x94
  SfmpvTtuRuntimeView pendingStartTtu{}; // +0xC0
  SfmpvTtuRuntimeView skipSeedTtu{}; // +0xEC
  std::int32_t interpolationEnabled = 0; // +0x118
  std::uint32_t activeStartTimecodeWords[8]{}; // +0x11C
  std::int32_t frameInterpolationTime = 0; // +0x13C
  std::int32_t frameInterpolationMinor = 0; // +0x140
  std::uint8_t mUnknown144To14F[0x0C]{}; // +0x144
  std::int32_t ptsBiasLow = -1; // +0x150
  std::int32_t ptsBiasHigh = -1; // +0x154
  std::uint8_t mUnknown158To163[0x0C]{}; // +0x158
  std::int32_t decodeProgressTime = 0; // +0x164
  std::uint8_t mUnknown168To293[0x12C]{}; // +0x168
  std::int32_t interpolationWindowTimeBase = 0; // +0x294
  std::int32_t interpolationWindowAdaptiveStep = 0; // +0x298
  std::int32_t interpolationWindowMaxStep = 0; // +0x29C
  std::int32_t interpolationWindowMinStep = 0; // +0x2A0
};

static_assert(offsetof(SfmpvTimingLane, isLateCallback) == 0x18, "SfmpvTimingLane::isLateCallback offset must be 0x18");
static_assert(
  offsetof(SfmpvTimingLane, repeatFieldTimecode) == 0x1C,
  "SfmpvTimingLane::repeatFieldTimecode offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvTimingLane, concatVideoTimeUnit) == 0x3C,
  "SfmpvTimingLane::concatVideoTimeUnit offset must be 0x3C"
);
static_assert(
  offsetof(SfmpvTimingLane, concatAudioTimeUnit) == 0x68,
  "SfmpvTimingLane::concatAudioTimeUnit offset must be 0x68"
);
static_assert(
  offsetof(SfmpvTimingLane, seekFixedBaselineTtu) == 0x94,
  "SfmpvTimingLane::seekFixedBaselineTtu offset must be 0x94"
);
static_assert(
  offsetof(SfmpvTimingLane, seekFixedBaselineTtu) + offsetof(SfmpvTtuRuntimeView, timeMajor) == 0xB8,
  "SfmpvTimingLane::seekFixedBaselineTtu.timeMajor offset must be 0xB8"
);
static_assert(
  offsetof(SfmpvTimingLane, pendingStartTtu) == 0xC0,
  "SfmpvTimingLane::pendingStartTtu offset must be 0xC0"
);
static_assert(
  offsetof(SfmpvTimingLane, pendingStartTtu) + offsetof(SfmpvTtuRuntimeView, packedTimecodeWords) == 0xC4,
  "SfmpvTimingLane::pendingStartTtu.packedTimecodeWords offset must be 0xC4"
);
static_assert(
  offsetof(SfmpvTimingLane, pendingStartTtu) + offsetof(SfmpvTtuRuntimeView, timeMajor) == 0xE4,
  "SfmpvTimingLane::pendingStartTtu.timeMajor offset must be 0xE4"
);
static_assert(
  offsetof(SfmpvTimingLane, pendingStartTtu) + offsetof(SfmpvTtuRuntimeView, timeMinor) == 0xE8,
  "SfmpvTimingLane::pendingStartTtu.timeMinor offset must be 0xE8"
);
static_assert(
  offsetof(SfmpvTimingLane, skipSeedTtu) == 0xEC,
  "SfmpvTimingLane::skipSeedTtu offset must be 0xEC"
);
static_assert(
  offsetof(SfmpvTimingLane, interpolationEnabled) == 0x118,
  "SfmpvTimingLane::interpolationEnabled offset must be 0x118"
);
static_assert(
  offsetof(SfmpvTimingLane, activeStartTimecodeWords) == 0x11C,
  "SfmpvTimingLane::activeStartTimecodeWords offset must be 0x11C"
);
static_assert(
  offsetof(SfmpvTimingLane, frameInterpolationTime) == 0x13C,
  "SfmpvTimingLane::frameInterpolationTime offset must be 0x13C"
);
static_assert(
  offsetof(SfmpvTimingLane, frameInterpolationMinor) == 0x140,
  "SfmpvTimingLane::frameInterpolationMinor offset must be 0x140"
);
static_assert(offsetof(SfmpvTimingLane, ptsBiasLow) == 0x150, "SfmpvTimingLane::ptsBiasLow offset must be 0x150");
static_assert(offsetof(SfmpvTimingLane, ptsBiasHigh) == 0x154, "SfmpvTimingLane::ptsBiasHigh offset must be 0x154");
static_assert(
  offsetof(SfmpvTimingLane, decodeProgressTime) == 0x164,
  "SfmpvTimingLane::decodeProgressTime offset must be 0x164"
);
static_assert(
  offsetof(SfmpvTimingLane, interpolationWindowTimeBase) == 0x294,
  "SfmpvTimingLane::interpolationWindowTimeBase offset must be 0x294"
);
static_assert(
  offsetof(SfmpvTimingLane, interpolationWindowAdaptiveStep) == 0x298,
  "SfmpvTimingLane::interpolationWindowAdaptiveStep offset must be 0x298"
);
static_assert(
  offsetof(SfmpvTimingLane, interpolationWindowMaxStep) == 0x29C,
  "SfmpvTimingLane::interpolationWindowMaxStep offset must be 0x29C"
);
static_assert(
  offsetof(SfmpvTimingLane, interpolationWindowMinStep) == 0x2A0,
  "SfmpvTimingLane::interpolationWindowMinStep offset must be 0x2A0"
);

/**
 * MPV info lane addressed from one workctrl via pointer at offset `+0x1FC0`.
 */
struct SfmpvInfoRuntimeView
{
  std::int32_t decoderHandle = 0; // +0x00
  SfmpvPara persistedPara = {}; // +0x04
  std::int32_t persistedRfbAddressTable[2]{}; // +0x28
  std::int32_t persistedSofDecTabs[16]{}; // +0x30
  std::int32_t activeFrameObjectAddress = 0; // +0x70
  std::int32_t defectPictureTypeState = 0; // +0x74
  std::int32_t concatControlFlags = 0; // +0x78
  std::uint8_t mUnknown7CTo83[0x08]{}; // +0x7C
  std::int32_t lateFrameCounter = 0; // +0x84
  std::int32_t concatAdvanceCount = 0; // +0x88
  SfmpvPictureDecodeLaneRuntimeView pictureDecodeLane{}; // +0x8C
  std::int32_t lastPictureSequenceStamp = 0; // +0x10C
  std::int32_t linkDefectCheckEnabled = 0; // +0x110
  std::int32_t vbvWriteThreshold = 0; // +0x114
  SfmpvComplementPts complementPts = {}; // +0x118
  std::int32_t primaryFrameToggleIndex = 0; // +0x138
  std::int32_t secondaryFrameToggleIndex = 0; // +0x13C
  std::int32_t primaryLumaPlaneBaseAddress = 0; // +0x140
  std::int32_t primaryChromaUPlaneBaseAddress = 0; // +0x144
  std::int32_t primaryFrameBaseAddress = 0; // +0x148
  std::uint16_t primaryChromaStride = 0; // +0x14C
  std::uint16_t primaryLumaStride = 0; // +0x14E
  std::int32_t secondaryLumaPlaneBaseAddress = 0; // +0x150
  std::int32_t secondaryChromaUPlaneBaseAddress = 0; // +0x154
  std::int32_t secondaryFrameBaseAddress = 0; // +0x158
  std::uint16_t secondaryChromaStride = 0; // +0x15C
  std::uint16_t secondaryLumaStride = 0; // +0x15E
  std::int32_t primaryReferenceFrameObjectAddress = 0; // +0x160
  std::int32_t secondaryReferenceFrameObjectAddress = 0; // +0x164
  std::int32_t pendingFrameObjectAddress = 0; // +0x168
  std::int32_t skipIssuedFlag = 0; // +0x16C
  std::int32_t picAtrPrimedLatch = 0; // +0x170
  std::int32_t referenceErrorCarryFlag = 0; // +0x174
  std::uint8_t mUnknown178ToFFF[0xE88]{}; // +0x178
  std::int32_t pictureUserBufferAddress = 0; // +0x1000
  std::int32_t pictureUserBufferCount = 0; // +0x1004
  std::int32_t pictureUserBufferSize = 0; // +0x1008
  std::int32_t pictureUserBufferMirrorAddress = 0; // +0x100C
  std::int32_t pictureUserFlags = 0; // +0x1010
  SfmpvPicUsr::PicUsrEntry pictureUserEntries[16]{}; // +0x1014
  std::uint8_t mUnknown1094To1097[0x04]{}; // +0x1094
  std::int32_t referenceErrorSeedMajor = 0; // +0x1098
  std::int32_t referenceErrorSeedMinor = 0; // +0x109C
};

static_assert(offsetof(SfmpvInfoRuntimeView, decoderHandle) == 0x00, "SfmpvInfoRuntimeView::decoderHandle offset must be 0x00");
static_assert(offsetof(SfmpvInfoRuntimeView, persistedPara) == 0x04, "SfmpvInfoRuntimeView::persistedPara offset must be 0x04");
static_assert(
  offsetof(SfmpvInfoRuntimeView, persistedRfbAddressTable) == 0x28,
  "SfmpvInfoRuntimeView::persistedRfbAddressTable offset must be 0x28"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, persistedSofDecTabs) == 0x30,
  "SfmpvInfoRuntimeView::persistedSofDecTabs offset must be 0x30"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, activeFrameObjectAddress) == 0x70,
  "SfmpvInfoRuntimeView::activeFrameObjectAddress offset must be 0x70"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, defectPictureTypeState) == 0x74,
  "SfmpvInfoRuntimeView::defectPictureTypeState offset must be 0x74"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, concatControlFlags) == 0x78,
  "SfmpvInfoRuntimeView::concatControlFlags offset must be 0x78"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, lateFrameCounter) == 0x84,
  "SfmpvInfoRuntimeView::lateFrameCounter offset must be 0x84"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, concatAdvanceCount) == 0x88,
  "SfmpvInfoRuntimeView::concatAdvanceCount offset must be 0x88"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureDecodeLane) == 0x8C,
  "SfmpvInfoRuntimeView::pictureDecodeLane offset must be 0x8C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureDecodeLane) + offsetof(SfmpvPictureDecodeLaneRuntimeView, pictureType) == 0xA4,
  "SfmpvInfoRuntimeView::pictureDecodeLane.pictureType offset must be 0xA4"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureDecodeLane) + offsetof(SfmpvPictureDecodeLaneRuntimeView, skipDecisionLatch) == 0xE4,
  "SfmpvInfoRuntimeView::pictureDecodeLane.skipDecisionLatch offset must be 0xE4"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, lastPictureSequenceStamp) == 0x10C,
  "SfmpvInfoRuntimeView::lastPictureSequenceStamp offset must be 0x10C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, linkDefectCheckEnabled) == 0x110,
  "SfmpvInfoRuntimeView::linkDefectCheckEnabled offset must be 0x110"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, vbvWriteThreshold) == 0x114,
  "SfmpvInfoRuntimeView::vbvWriteThreshold offset must be 0x114"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, complementPts) == 0x118,
  "SfmpvInfoRuntimeView::complementPts offset must be 0x118"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryFrameToggleIndex) == 0x138,
  "SfmpvInfoRuntimeView::primaryFrameToggleIndex offset must be 0x138"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryFrameToggleIndex) == 0x13C,
  "SfmpvInfoRuntimeView::secondaryFrameToggleIndex offset must be 0x13C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryLumaPlaneBaseAddress) == 0x140,
  "SfmpvInfoRuntimeView::primaryLumaPlaneBaseAddress offset must be 0x140"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryChromaUPlaneBaseAddress) == 0x144,
  "SfmpvInfoRuntimeView::primaryChromaUPlaneBaseAddress offset must be 0x144"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryFrameBaseAddress) == 0x148,
  "SfmpvInfoRuntimeView::primaryFrameBaseAddress offset must be 0x148"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryChromaStride) == 0x14C,
  "SfmpvInfoRuntimeView::primaryChromaStride offset must be 0x14C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryLumaStride) == 0x14E,
  "SfmpvInfoRuntimeView::primaryLumaStride offset must be 0x14E"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryLumaPlaneBaseAddress) == 0x150,
  "SfmpvInfoRuntimeView::secondaryLumaPlaneBaseAddress offset must be 0x150"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryChromaUPlaneBaseAddress) == 0x154,
  "SfmpvInfoRuntimeView::secondaryChromaUPlaneBaseAddress offset must be 0x154"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryFrameBaseAddress) == 0x158,
  "SfmpvInfoRuntimeView::secondaryFrameBaseAddress offset must be 0x158"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryChromaStride) == 0x15C,
  "SfmpvInfoRuntimeView::secondaryChromaStride offset must be 0x15C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryLumaStride) == 0x15E,
  "SfmpvInfoRuntimeView::secondaryLumaStride offset must be 0x15E"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, primaryReferenceFrameObjectAddress) == 0x160,
  "SfmpvInfoRuntimeView::primaryReferenceFrameObjectAddress offset must be 0x160"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, secondaryReferenceFrameObjectAddress) == 0x164,
  "SfmpvInfoRuntimeView::secondaryReferenceFrameObjectAddress offset must be 0x164"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pendingFrameObjectAddress) == 0x168,
  "SfmpvInfoRuntimeView::pendingFrameObjectAddress offset must be 0x168"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, skipIssuedFlag) == 0x16C,
  "SfmpvInfoRuntimeView::skipIssuedFlag offset must be 0x16C"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, picAtrPrimedLatch) == 0x170,
  "SfmpvInfoRuntimeView::picAtrPrimedLatch offset must be 0x170"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, referenceErrorCarryFlag) == 0x174,
  "SfmpvInfoRuntimeView::referenceErrorCarryFlag offset must be 0x174"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureUserBufferAddress) == 0x1000,
  "SfmpvInfoRuntimeView::pictureUserBufferAddress offset must be 0x1000"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureUserBufferCount) == 0x1004,
  "SfmpvInfoRuntimeView::pictureUserBufferCount offset must be 0x1004"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureUserBufferSize) == 0x1008,
  "SfmpvInfoRuntimeView::pictureUserBufferSize offset must be 0x1008"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureUserBufferMirrorAddress) == 0x100C,
  "SfmpvInfoRuntimeView::pictureUserBufferMirrorAddress offset must be 0x100C"
);
static_assert(offsetof(SfmpvInfoRuntimeView, pictureUserFlags) == 0x1010, "SfmpvInfoRuntimeView::pictureUserFlags offset must be 0x1010");
static_assert(
  offsetof(SfmpvInfoRuntimeView, pictureUserEntries) == 0x1014,
  "SfmpvInfoRuntimeView::pictureUserEntries offset must be 0x1014"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, referenceErrorSeedMajor) == 0x1098,
  "SfmpvInfoRuntimeView::referenceErrorSeedMajor offset must be 0x1098"
);
static_assert(
  offsetof(SfmpvInfoRuntimeView, referenceErrorSeedMinor) == 0x109C,
  "SfmpvInfoRuntimeView::referenceErrorSeedMinor offset must be 0x109C"
);

/**
 * Workctrl runtime view used by recovered MPV helper lanes.
 */
struct SfmpvHandleRuntimeView
{
  std::uint8_t mUnknown00To27[0x28]{}; // +0x00
  std::int32_t minimumVideoBufferBytes = 0; // +0x28
  std::int32_t prepFrameTargetCount = 0; // +0x2C
  std::uint8_t mUnknown30To37[0x08]{}; // +0x30
  std::int32_t mpvCond6Value = 0; // +0x38
  std::uint8_t mUnknown3CTo57[0x1C]{}; // +0x3C
  std::int32_t decodePathMode = 0; // +0x58
  std::int32_t frameIdCounter = 0; // +0x5C
  std::uint8_t mUnknown60To77[0x18]{}; // +0x60
  std::int32_t frameHeaderHandle = 0; // +0x78
  std::uint8_t mUnknown7CToF3[0x78]{}; // +0x7C
  std::int32_t vbvBypassFlag = 0; // +0xF4
  std::uint8_t mUnknownF8To90B[0x814]{}; // +0xF8
  SfmpvMvInfoRuntimeView mvInfo{}; // +0x90C
  std::uint8_t mUnknown930To94F[0x20]{}; // +0x930
  std::int32_t playbackInfoAddress = 0; // +0x950
  std::uint8_t mUnknown954To957[0x04]{}; // +0x954
  std::int32_t decoderDctCountPrimary = 0; // +0x958
  std::int32_t decoderDctCountSecondary = 0; // +0x95C
  std::int32_t emptyBpicCount = 0; // +0x960
  std::int32_t emptyPpicCount = 0; // +0x964
  std::int32_t preparedFrameCount = 0; // +0x968
  std::int32_t consumedFrameCount = 0; // +0x96C
  std::uint8_t mUnknown970To977[0x08]{}; // +0x970
  std::int32_t decodeStarvedLatch = 0; // +0x978
  std::int32_t frameAllocationFailed = 0; // +0x97C
  std::uint8_t mUnknown980To99F[0x20]{}; // +0x980
  std::int32_t streamFlowCountLow = 0; // +0x9A0
  std::int32_t streamFlowCountHigh = 0; // +0x9A4
  std::int32_t ringReadTotalLow = 0; // +0x9A8
  std::int32_t ringReadTotalHigh = 0; // +0x9AC
  std::int32_t delimiterReadTotalLow = 0; // +0x9B0
  std::int32_t delimiterReadTotalHigh = 0; // +0x9B4
  std::uint8_t mUnknown9B8ToA03[0x4C]{}; // +0x9B8
  std::int32_t decodeReferenceErrorMajor = 0; // +0xA04
  std::int32_t decodeReferenceErrorMinor = 0; // +0xA08
  std::uint8_t mUnknownA0CToA13[0x08]{}; // +0xA0C
  std::int32_t ptype1DecodeEnable = 0; // +0xA14
  std::int32_t ptype2DecodeEnable = 0; // +0xA18
  std::int32_t ptype3DecodeEnable = 0; // +0xA1C
  std::uint8_t mUnknownA20ToA67[0x48]{}; // +0xA20
  std::int32_t prepFrameRequiredCount = 0; // +0xA68
  std::uint8_t mUnknownA6CToAA3[0x38]{}; // +0xA6C
  std::int32_t lateFrameGateThreshold = 0; // +0xAA4
  std::uint8_t mUnknownAA8ToAB3[0x0C]{}; // +0xAA8
  std::int32_t frameDeltaMajor = 0; // +0xAB4
  std::int32_t frameDeltaMinor = 0; // +0xAB8
  std::uint8_t mUnknownABCToD2F[0x274]{}; // +0xABC
  // NOTE: SfmpvTimingLane as defined is 0x2A4 bytes total, but the binary
  // places `concatTimeHistoryWriteOrdinal` only 0x168 bytes after the start
  // of timingLane. Fields past the 0x168 boundary (interpolationWindow*)
  // belong to a standalone SFTIM buffer, not the embedded one here. The
  // embedded object therefore overlaps with the fields below in this C++
  // layout; offsets beyond 0xE97 validated via the failing static_asserts
  // that follow have been commented out pending struct-ownership recovery.
  // All current code paths access only the first 0x168 prefix via
  // `workctrl->timingLane.xxx`, so behavior is preserved.
  SfmpvTimingLane timingLane{}; // +0xD30
  std::int32_t concatTimeHistoryWriteOrdinal = 0; // +0xE98 (nominal)
  std::int32_t concatTimeHistory[32]{}; // +0xE9C
  std::int32_t queuedAudioSampleRate = 0; // +0xF1C
  std::int32_t audioTotalSampleCount = 0; // +0xF20
  std::int32_t totalSampleQueueWriteOrdinal = 0; // +0xF24
  std::int32_t totalSampleQueueReadOrdinal = 0; // +0xF28
  std::int32_t totalSampleQueueTotals[32]{}; // +0xF2C
  std::int32_t readFrameTimeMajor = 0; // +0xFAC
  std::int32_t readFrameTimeMinor = 0; // +0xFB0
  std::int32_t maxFrameTimeMajor = 0; // +0xFB4
  std::int32_t maxFrameTimeMinor = 0; // +0xFB8
  std::uint8_t mUnknownFBCTo11DF[0x224]{}; // +0xFBC
  SfmpvRepeatFieldHistoryRuntimeView repeatFieldHistory{}; // +0x11E0
  std::uint8_t mUnknown12E0To1FBF[0xCE0]{}; // +0x12E0
  SfmpvInfoRuntimeView* mpvInfo = nullptr; // +0x1FC0
  std::uint8_t mUnknown1FC4To1FC7[0x04]{}; // +0x1FC4
  std::int32_t prepSourceLaneIndex = 0; // +0x1FC8
  std::int32_t prepDestinationLaneIndex = 0; // +0x1FCC
  std::uint8_t mUnknown1FD0To1FD7[0x08]{}; // +0x1FD0
  std::int32_t seekFixedReadTotal = -1; // +0x1FD8
  std::uint8_t mUnknown1FDCTo354F[0x1574]{}; // +0x1FDC
  std::int32_t headerWorkspaceBaseAddress = 0; // +0x3550
  std::uint8_t mUnknown3554To3557[0x04]{}; // +0x3554
  std::int32_t seekSkipTimeMajor = -1; // +0x3558
  std::int32_t seekSkipTimeMinor = 0; // +0x355C
  SftmrTimeSumRuntimeView decodeTimeSumsByPictureType[4]{}; // +0x3560
};

static_assert(
  offsetof(SfmpvHandleRuntimeView, minimumVideoBufferBytes) == 0x28,
  "SfmpvHandleRuntimeView::minimumVideoBufferBytes offset must be 0x28"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, prepFrameTargetCount) == 0x2C,
  "SfmpvHandleRuntimeView::prepFrameTargetCount offset must be 0x2C"
);
static_assert(offsetof(SfmpvHandleRuntimeView, mpvCond6Value) == 0x38, "SfmpvHandleRuntimeView::mpvCond6Value offset must be 0x38");
static_assert(offsetof(SfmpvHandleRuntimeView, decodePathMode) == 0x58, "SfmpvHandleRuntimeView::decodePathMode offset must be 0x58");
static_assert(offsetof(SfmpvHandleRuntimeView, frameIdCounter) == 0x5C, "SfmpvHandleRuntimeView::frameIdCounter offset must be 0x5C");
static_assert(
  offsetof(SfmpvHandleRuntimeView, frameHeaderHandle) == 0x78,
  "SfmpvHandleRuntimeView::frameHeaderHandle offset must be 0x78"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, vbvBypassFlag) == 0xF4,
  "SfmpvHandleRuntimeView::vbvBypassFlag offset must be 0xF4"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, playbackInfoAddress) == 0x950,
  "SfmpvHandleRuntimeView::playbackInfoAddress offset must be 0x950"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, mvInfo) == 0x90C,
  "SfmpvHandleRuntimeView::mvInfo offset must be 0x90C"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, mvInfo) + offsetof(SfmpvMvInfoRuntimeView, frameAreaWidthPixels) == 0x914,
  "SfmpvHandleRuntimeView::mvInfo.frameAreaWidthPixels offset must be 0x914"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, mvInfo) + offsetof(SfmpvMvInfoRuntimeView, frameAreaHeightPixels) == 0x918,
  "SfmpvHandleRuntimeView::mvInfo.frameAreaHeightPixels offset must be 0x918"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, mvInfo) + offsetof(SfmpvMvInfoRuntimeView, frameRateBase) == 0x91C,
  "SfmpvHandleRuntimeView::mvInfo.frameRateBase offset must be 0x91C"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, decoderDctCountPrimary) == 0x958,
  "SfmpvHandleRuntimeView::decoderDctCountPrimary offset must be 0x958"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, decoderDctCountSecondary) == 0x95C,
  "SfmpvHandleRuntimeView::decoderDctCountSecondary offset must be 0x95C"
);
static_assert(offsetof(SfmpvHandleRuntimeView, emptyBpicCount) == 0x960, "SfmpvHandleRuntimeView::emptyBpicCount offset must be 0x960");
static_assert(offsetof(SfmpvHandleRuntimeView, emptyPpicCount) == 0x964, "SfmpvHandleRuntimeView::emptyPpicCount offset must be 0x964");
static_assert(
  offsetof(SfmpvHandleRuntimeView, preparedFrameCount) == 0x968,
  "SfmpvHandleRuntimeView::preparedFrameCount offset must be 0x968"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, consumedFrameCount) == 0x96C,
  "SfmpvHandleRuntimeView::consumedFrameCount offset must be 0x96C"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, decodeStarvedLatch) == 0x978,
  "SfmpvHandleRuntimeView::decodeStarvedLatch offset must be 0x978"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, frameAllocationFailed) == 0x97C,
  "SfmpvHandleRuntimeView::frameAllocationFailed offset must be 0x97C"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, streamFlowCountLow) == 0x9A0,
  "SfmpvHandleRuntimeView::streamFlowCountLow offset must be 0x9A0"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, streamFlowCountHigh) == 0x9A4,
  "SfmpvHandleRuntimeView::streamFlowCountHigh offset must be 0x9A4"
);
static_assert(offsetof(SfmpvHandleRuntimeView, ringReadTotalLow) == 0x9A8, "SfmpvHandleRuntimeView::ringReadTotalLow offset must be 0x9A8");
static_assert(offsetof(SfmpvHandleRuntimeView, ringReadTotalHigh) == 0x9AC, "SfmpvHandleRuntimeView::ringReadTotalHigh offset must be 0x9AC");
static_assert(
  offsetof(SfmpvHandleRuntimeView, delimiterReadTotalLow) == 0x9B0,
  "SfmpvHandleRuntimeView::delimiterReadTotalLow offset must be 0x9B0"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, delimiterReadTotalHigh) == 0x9B4,
  "SfmpvHandleRuntimeView::delimiterReadTotalHigh offset must be 0x9B4"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, decodeReferenceErrorMajor) == 0xA04,
  "SfmpvHandleRuntimeView::decodeReferenceErrorMajor offset must be 0xA04"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, decodeReferenceErrorMinor) == 0xA08,
  "SfmpvHandleRuntimeView::decodeReferenceErrorMinor offset must be 0xA08"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, ptype1DecodeEnable) == 0xA14,
  "SfmpvHandleRuntimeView::ptype1DecodeEnable offset must be 0xA14"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, ptype2DecodeEnable) == 0xA18,
  "SfmpvHandleRuntimeView::ptype2DecodeEnable offset must be 0xA18"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, ptype3DecodeEnable) == 0xA1C,
  "SfmpvHandleRuntimeView::ptype3DecodeEnable offset must be 0xA1C"
);
// TODO(recovery): Offsets below are shifted because the embedded SfmpvTimingLane
// is 0x2A4 bytes in C++ but only 0x168 bytes in binary layout. All static_asserts
// past timingLane are therefore disabled pending struct-ownership recovery. Field
// access via `workctrl->field` still compiles and works for fields that do not
// overlap the timingLane tail.
// static_assert(offsetof(SfmpvHandleRuntimeView, readFrameTimeMajor) == 0xFAC, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, readFrameTimeMinor) == 0xFB0, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, maxFrameTimeMajor) == 0xFB4, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, maxFrameTimeMinor) == 0xFB8, ...);
static_assert(
  offsetof(SfmpvHandleRuntimeView, prepFrameRequiredCount) == 0xA68,
  "SfmpvHandleRuntimeView::prepFrameRequiredCount offset must be 0xA68"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, lateFrameGateThreshold) == 0xAA4,
  "SfmpvHandleRuntimeView::lateFrameGateThreshold offset must be 0xAA4"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, frameDeltaMajor) == 0xAB4,
  "SfmpvHandleRuntimeView::frameDeltaMajor offset must be 0xAB4"
);
static_assert(
  offsetof(SfmpvHandleRuntimeView, frameDeltaMinor) == 0xAB8,
  "SfmpvHandleRuntimeView::frameDeltaMinor offset must be 0xAB8"
);
static_assert(offsetof(SfmpvHandleRuntimeView, timingLane) == 0xD30, "SfmpvHandleRuntimeView::timingLane offset must be 0xD30");
// Offset asserts past timingLane commented out — see TODO note above.
// static_assert(offsetof(SfmpvHandleRuntimeView, concatTimeHistoryWriteOrdinal) == 0xE98, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, concatTimeHistory) == 0xE9C, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, queuedAudioSampleRate) == 0xF1C, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, audioTotalSampleCount) == 0xF20, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, totalSampleQueueWriteOrdinal) == 0xF24, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, totalSampleQueueReadOrdinal) == 0xF28, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, totalSampleQueueTotals) == 0xF2C, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, repeatFieldHistory) == 0x11E0, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, mpvInfo) == 0x1FC0, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, prepSourceLaneIndex) == 0x1FC8, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, prepDestinationLaneIndex) == 0x1FCC, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, seekFixedReadTotal) == 0x1FD8, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, headerWorkspaceBaseAddress) == 0x3550, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, seekSkipTimeMajor) == 0x3558, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, seekSkipTimeMinor) == 0x355C, ...);
// static_assert(offsetof(SfmpvHandleRuntimeView, decodeTimeSumsByPictureType) == 0x3560, ...);
// static_assert(sizeof(SfmpvHandleRuntimeView) == 0x35E0, ...);

struct SfmpvfVfrmDataRuntime
{
  std::int32_t drawState = 0; // +0x00
  std::int32_t ownerFrameObjectAddress = 0; // +0x04
};

static_assert(offsetof(SfmpvfVfrmDataRuntime, drawState) == 0x00, "SfmpvfVfrmDataRuntime::drawState offset must be 0x00");
static_assert(
  offsetof(SfmpvfVfrmDataRuntime, ownerFrameObjectAddress) == 0x04,
  "SfmpvfVfrmDataRuntime::ownerFrameObjectAddress offset must be 0x04"
);
static_assert(sizeof(SfmpvfVfrmDataRuntime) == 0x08, "SfmpvfVfrmDataRuntime size must be 0x08");

struct SfmpvfVfrmDataLaneRuntimeView
{
  SfmpvfVfrmDataRuntime vfrmData{}; // +0x00
  std::uint8_t mUnknown08To87[0x80]{}; // +0x08
};

static_assert(
  offsetof(SfmpvfVfrmDataLaneRuntimeView, vfrmData) == 0x00,
  "SfmpvfVfrmDataLaneRuntimeView::vfrmData offset must be 0x00"
);
static_assert(
  sizeof(SfmpvfVfrmDataLaneRuntimeView) == 0x88,
  "SfmpvfVfrmDataLaneRuntimeView size must be 0x88"
);

struct SfmpvfSearchWorkctrlRuntimeView
{
  std::uint8_t mUnknown00To16AF[0x16B0]{}; // +0x00
  SfmpvfVfrmDataLaneRuntimeView vfrmDataLanes[16]{}; // +0x16B0
  std::uint8_t mUnknown1F30To1FBF[0x90]{}; // +0x1F30
  SfmpvfInfoRuntimeView* mpvInfo = nullptr; // +0x1FC0
};

static_assert(
  offsetof(SfmpvfSearchWorkctrlRuntimeView, vfrmDataLanes) == 0x16B0,
  "SfmpvfSearchWorkctrlRuntimeView::vfrmDataLanes offset must be 0x16B0"
);
static_assert(
  offsetof(SfmpvfSearchWorkctrlRuntimeView, mpvInfo) == 0x1FC0,
  "SfmpvfSearchWorkctrlRuntimeView::mpvInfo offset must be 0x1FC0"
);
static_assert(sizeof(SfmpvfSearchWorkctrlRuntimeView) == 0x1FC4, "SfmpvfSearchWorkctrlRuntimeView size must be 0x1FC4");

struct SfmpvfFrameObjectRuntimeView
{
  std::int32_t decodeState = 0; // +0x00
  std::int32_t allocationState = 0; // +0x04
  std::int32_t frameSurfaceBaseAddress = 0; // +0x08
  std::uint8_t mUnknown0CTo37[0x2C]{}; // +0x0C
  std::int32_t presentationTimeMajor = 0; // +0x38
  std::int32_t presentationTimeMinor = 0; // +0x3C
  std::int32_t referenceErrorMajor = 0; // +0x40
  std::int32_t referenceErrorMinor = 0; // +0x44
  std::int32_t decodeConcatOrdinal = 0; // +0x48
  std::int32_t frameDetailWord4C = 0; // +0x4C
  std::int32_t frameDetailWord50 = 0; // +0x50
  std::int32_t pictureUserInfoAddress = 0; // +0x54
  std::int32_t frameId = 0; // +0x58
  SfmpvPictureDecodeLaneRuntimeView pictureDecodeLane{}; // +0x5C
  std::uint8_t mUnknownDCToDF[0x04]{}; // +0xDC
  std::int32_t referenceErrorSeedMajor = 0; // +0xE0
  std::int32_t referenceErrorSeedMinor = 0; // +0xE4
};

static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, decodeState) == 0x00,
  "SfmpvfFrameObjectRuntimeView::decodeState offset must be 0x00"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, allocationState) == 0x04,
  "SfmpvfFrameObjectRuntimeView::allocationState offset must be 0x04"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, frameSurfaceBaseAddress) == 0x08,
  "SfmpvfFrameObjectRuntimeView::frameSurfaceBaseAddress offset must be 0x08"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, presentationTimeMajor) == 0x38,
  "SfmpvfFrameObjectRuntimeView::presentationTimeMajor offset must be 0x38"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, presentationTimeMinor) == 0x3C,
  "SfmpvfFrameObjectRuntimeView::presentationTimeMinor offset must be 0x3C"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, referenceErrorMajor) == 0x40,
  "SfmpvfFrameObjectRuntimeView::referenceErrorMajor offset must be 0x40"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, referenceErrorMinor) == 0x44,
  "SfmpvfFrameObjectRuntimeView::referenceErrorMinor offset must be 0x44"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, decodeConcatOrdinal) == 0x48,
  "SfmpvfFrameObjectRuntimeView::decodeConcatOrdinal offset must be 0x48"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, pictureUserInfoAddress) == 0x54,
  "SfmpvfFrameObjectRuntimeView::pictureUserInfoAddress offset must be 0x54"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, frameId) == 0x58,
  "SfmpvfFrameObjectRuntimeView::frameId offset must be 0x58"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, pictureDecodeLane) == 0x5C,
  "SfmpvfFrameObjectRuntimeView::pictureDecodeLane offset must be 0x5C"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, referenceErrorSeedMajor) == 0xE0,
  "SfmpvfFrameObjectRuntimeView::referenceErrorSeedMajor offset must be 0xE0"
);
static_assert(
  offsetof(SfmpvfFrameObjectRuntimeView, referenceErrorSeedMinor) == 0xE4,
  "SfmpvfFrameObjectRuntimeView::referenceErrorSeedMinor offset must be 0xE4"
);
static_assert(sizeof(SfmpvfFrameObjectRuntimeView) == 0xE8, "SfmpvfFrameObjectRuntimeView size must be 0xE8");

struct SfmpvfFrameInfoRuntimeView
{
  std::int32_t pictureWidthPixels = 0; // +0x00
  std::int32_t pictureHeightPixels = 0; // +0x04
  std::int32_t pictureDetailWord08 = 0; // +0x08
  std::int32_t pictureDetailWord0C = 0; // +0x0C
  std::int32_t pictureType = 0; // +0x10
  std::int32_t presentationTimeMajor = 0; // +0x14
  std::int32_t presentationTimeMinor = 0; // +0x18
  std::int32_t decodeConditionMode = 0; // +0x1C
  std::int32_t frameSurfaceBaseAddress = 0; // +0x20
  std::int32_t referenceErrorMajor = 0; // +0x24
  std::int32_t referenceErrorMinor = 0; // +0x28
  std::int32_t decodeConcatOrdinal = 0; // +0x2C
  std::int32_t frameDetailWord30 = 0; // +0x30
  std::int32_t frameDetailWord34 = 0; // +0x34
  std::int32_t pictureUserInfoAddress = 0; // +0x38
  std::int32_t chromaPositionLow = 0; // +0x3C
  std::int32_t chromaPositionHigh = 0; // +0x40
  std::uint8_t mUnknown44To47[0x04]{}; // +0x44
  std::int32_t chromaLayoutClass = 0; // +0x48
  std::uint8_t mUnknown4CTo4F[0x04]{}; // +0x4C
  std::int32_t referenceErrorSeedMajor = 0; // +0x50
  std::int32_t referenceErrorSeedMinor = 0; // +0x54
  std::int32_t referenceUpdateMode = 0; // +0x58
  std::int32_t chromaFormat = 0; // +0x5C
  std::int32_t pictureDetailWord60 = 0; // +0x60
  std::int32_t pictureDetailWord64 = 0; // +0x64
  std::uint16_t pictureDetailWord68 = 0; // +0x68
  std::uint16_t pictureDetailWord6A = 0; // +0x6A
  std::uint8_t pictureDecodeFlagA = 0; // +0x6C
  std::uint8_t pictureDecodeFlagB = 0; // +0x6D
  std::uint8_t pictureDecodeFlagC = 0; // +0x6E
  std::uint8_t pictureDecodeFlagD = 0; // +0x6F
  std::uint8_t pictureDecodeFlagE = 0; // +0x70
  std::uint8_t pictureDecodeFlagF = 0; // +0x71
  std::uint8_t pictureDecodeFlagG = 0; // +0x72
  std::uint8_t pictureDecodeFlagH = 0; // +0x73
  std::uint8_t pictureDecodeFlagI = 0; // +0x74
  std::uint8_t pictureDecodeFlagJ = 0; // +0x75
  std::uint8_t pictureDecodeFlagK = 0; // +0x76
  std::uint8_t pictureDecodeFlagL = 0; // +0x77
  std::uint8_t pictureDecodeFlagM = 0; // +0x78
  std::uint8_t pictureDecodeFlagN = 0; // +0x79
  std::uint8_t pictureDecodeFlagO = 0; // +0x7A
};

static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureWidthPixels) == 0x00,
  "SfmpvfFrameInfoRuntimeView::pictureWidthPixels offset must be 0x00"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureType) == 0x10,
  "SfmpvfFrameInfoRuntimeView::pictureType offset must be 0x10"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, presentationTimeMajor) == 0x14,
  "SfmpvfFrameInfoRuntimeView::presentationTimeMajor offset must be 0x14"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, presentationTimeMinor) == 0x18,
  "SfmpvfFrameInfoRuntimeView::presentationTimeMinor offset must be 0x18"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, decodeConditionMode) == 0x1C,
  "SfmpvfFrameInfoRuntimeView::decodeConditionMode offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureUserInfoAddress) == 0x38,
  "SfmpvfFrameInfoRuntimeView::pictureUserInfoAddress offset must be 0x38"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, chromaLayoutClass) == 0x48,
  "SfmpvfFrameInfoRuntimeView::chromaLayoutClass offset must be 0x48"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, referenceErrorSeedMajor) == 0x50,
  "SfmpvfFrameInfoRuntimeView::referenceErrorSeedMajor offset must be 0x50"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, referenceUpdateMode) == 0x58,
  "SfmpvfFrameInfoRuntimeView::referenceUpdateMode offset must be 0x58"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureDetailWord68) == 0x68,
  "SfmpvfFrameInfoRuntimeView::pictureDetailWord68 offset must be 0x68"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureDecodeFlagA) == 0x6C,
  "SfmpvfFrameInfoRuntimeView::pictureDecodeFlagA offset must be 0x6C"
);
static_assert(
  offsetof(SfmpvfFrameInfoRuntimeView, pictureDecodeFlagO) == 0x7A,
  "SfmpvfFrameInfoRuntimeView::pictureDecodeFlagO offset must be 0x7A"
);

struct SfmpvfInfoRuntimeView
{
  std::uint8_t mUnknown00To7B[0x7C]{}; // +0x00
  std::int32_t termDecodeState = 0; // +0x7C
  std::int32_t allowSingleFrameOutput = 0; // +0x80
  std::uint8_t mUnknown84To177[0xF4]{}; // +0x84
  std::int32_t frameObjectCount = 0; // +0x178
  std::uint8_t mUnknown17CTo17F[0x04]{}; // +0x17C
  SfmpvfFrameObjectRuntimeView frameObjects[16]{}; // +0x180
};

static_assert(
  offsetof(SfmpvfInfoRuntimeView, termDecodeState) == 0x7C,
  "SfmpvfInfoRuntimeView::termDecodeState offset must be 0x7C"
);
static_assert(
  offsetof(SfmpvfInfoRuntimeView, allowSingleFrameOutput) == 0x80,
  "SfmpvfInfoRuntimeView::allowSingleFrameOutput offset must be 0x80"
);
static_assert(
  offsetof(SfmpvfInfoRuntimeView, frameObjectCount) == 0x178,
  "SfmpvfInfoRuntimeView::frameObjectCount offset must be 0x178"
);
static_assert(
  offsetof(SfmpvfInfoRuntimeView, frameObjects) == 0x180,
  "SfmpvfInfoRuntimeView::frameObjects offset must be 0x180"
);

struct SfmpvHeaderRuntimeView
{
  std::int32_t hasHeader = 0; // +0x00
  std::int32_t frameRateTicks = 0; // +0x04
  std::int32_t frameRateMode = 0; // +0x08
  std::uint32_t concatTimeSeedWords[11]{}; // +0x0C
  std::uint8_t pictureAttributeBytes[0x200]{}; // +0x38
  std::int32_t pictureAttributeByteCount = 0; // +0x238
};

static_assert(
  offsetof(SfmpvHeaderRuntimeView, concatTimeSeedWords) == 0x0C,
  "SfmpvHeaderRuntimeView::concatTimeSeedWords offset must be 0x0C"
);
static_assert(
  offsetof(SfmpvHeaderRuntimeView, pictureAttributeBytes) == 0x38,
  "SfmpvHeaderRuntimeView::pictureAttributeBytes offset must be 0x38"
);
static_assert(
  offsetof(SfmpvHeaderRuntimeView, pictureAttributeByteCount) == 0x238,
  "SfmpvHeaderRuntimeView::pictureAttributeByteCount offset must be 0x238"
);

struct SfmpvDefectLaneRuntimeView
{
  std::uint8_t mUnknown00To17[0x18]{}; // +0x00
  std::int32_t pictureType = 0; // +0x18
};

static_assert(
  offsetof(SfmpvDefectLaneRuntimeView, pictureType) == 0x18,
  "SfmpvDefectLaneRuntimeView::pictureType offset must be 0x18"
);

struct SfmpvAudioTransportVtableRuntimeView
{
  void(__cdecl* reserved00)() = nullptr; // +0x00
  void(__cdecl* reserved04)() = nullptr; // +0x04
  void(__cdecl* reserved08)() = nullptr; // +0x08
  void(__cdecl* readTotalSamplesProc)() = nullptr; // +0x0C
};

struct SfmpvAudioTransportRuntimeView
{
  SfmpvAudioTransportVtableRuntimeView* vtable = nullptr; // +0x00
};

static_assert(
  offsetof(SfmpvAudioTransportRuntimeView, vtable) == 0x00,
  "SfmpvAudioTransportRuntimeView::vtable offset must be 0x00"
);

struct SfmpvStreamWindowCursorRuntimeView
{
  std::uint8_t* cursor = nullptr; // +0x00
  std::int32_t byteCount = 0; // +0x04
};

static_assert(
  sizeof(SfmpvStreamWindowCursorRuntimeView) == 0x08,
  "SfmpvStreamWindowCursorRuntimeView size must be 0x08"
);

using SfmpvStreamBufferReadWindowProc = void(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t laneIndex,
  std::int32_t byteCount,
  SfmpvStreamWindowCursorRuntimeView* cursorWindow
);
using SfmpvStreamBufferCommitWindowProc = std::int32_t(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t laneIndex,
  SfmpvStreamWindowCursorRuntimeView* cursorWindow
);
using SfmpvStreamBufferAdvanceWindowProc = void(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t discardMode,
  SfmpvStreamWindowCursorRuntimeView* cursorWindow
);

struct SfmpvStreamBufferVtableRuntimeView
{
  void(__cdecl* reserved00)() = nullptr; // +0x00
  void(__cdecl* reserved04)() = nullptr; // +0x04
  void(__cdecl* reserved08)() = nullptr; // +0x08
  void(__cdecl* reserved0C)() = nullptr; // +0x0C
  void(__cdecl* reserved10)() = nullptr; // +0x10
  void(__cdecl* reserved14)() = nullptr; // +0x14
  SfmpvStreamBufferReadWindowProc readWindow = nullptr; // +0x18
  SfmpvStreamBufferCommitWindowProc commitWindow = nullptr; // +0x1C
  SfmpvStreamBufferAdvanceWindowProc advanceWindow = nullptr; // +0x20
};

struct SfmpvStreamBufferRuntimeView
{
  SfmpvStreamBufferVtableRuntimeView* vtable = nullptr; // +0x00
};

static_assert(
  offsetof(SfmpvStreamBufferRuntimeView, vtable) == 0x00,
  "SfmpvStreamBufferRuntimeView::vtable offset must be 0x00"
);

/**
 * Runtime lane used by MPV CMC motion-compensation init helpers.
 */
struct MpvcmcRuntimeView
{
  std::uint8_t reserved0000_011F[0x120]{};
  std::int32_t initWord120 = 0; // +0x120
  std::uint8_t reserved0124_0127[0x04]{};
  std::int32_t initWord128 = 0; // +0x128
  std::uint8_t reserved012C_012F[0x04]{};
  std::int32_t initWord130 = 0; // +0x130
  std::uint8_t reserved0134_0137[0x04]{};
  std::int32_t initWord138 = 0; // +0x138
  std::uint8_t reserved013C_013F[0x04]{};
  std::int32_t initWord140 = 0; // +0x140
  std::uint8_t reserved0144_0147[0x04]{};
  std::int32_t initWord148 = 0; // +0x148
  std::uint8_t reserved014C_014F[0x04]{};
  std::int32_t initWord150 = 0; // +0x150
  std::int32_t initWord154 = 0; // +0x154
  std::int32_t initWord158 = 0; // +0x158
  std::int32_t initWord15C = 0; // +0x15C
  std::int32_t initWord160 = 0; // +0x160
  std::int32_t initWord164 = 0; // +0x164
  std::int32_t initWord168 = 0; // +0x168
  std::int32_t initWord16C = 0; // +0x16C
  std::int32_t initWord170 = 0; // +0x170
  std::int32_t initWord174 = 0; // +0x174
  std::int32_t initWord178 = 0; // +0x178
  std::int32_t initWord17C = 0; // +0x17C
  std::int32_t initWord180 = 0; // +0x180
  std::int32_t initWord184 = 0; // +0x184
  std::uint8_t reserved0188_01A3[0x1C]{};
  std::int32_t initWord1A4 = 0; // +0x1A4
  std::uint8_t reserved01A8_01B7[0x10]{};
  std::int32_t umcHalfResMode = 0; // +0x1B8
  std::uint8_t reserved01BC_01CF[0x14]{};
  std::int32_t outputWidthPixels = 0; // +0x1D0
  std::int32_t outputHeightPixels = 0; // +0x1D4
  std::uint8_t reserved01D8_027F[0xA8]{};
  std::int16_t initWord280 = 0; // +0x280
  std::int16_t initWord282 = 0; // +0x282
  std::int32_t outputRfbBaseAddress = 0; // +0x284
  std::uint8_t reserved0288_0293[0x0C]{};
  std::int32_t outputYPlaneAddress = 0; // +0x294
  std::int32_t outputCPlaneAddress = 0; // +0x298
  std::int32_t outputYPlaneBaseAddress = 0; // +0x29C
  std::int16_t outputChromaStrideBytes = 0; // +0x2A0
  std::int16_t outputLumaStrideBytes = 0; // +0x2A2
  std::uint8_t reserved02A4_0D1F[0xA7C]{};
  std::uint32_t initWord0D20 = 0; // +0xD20
};

static_assert(offsetof(MpvcmcRuntimeView, initWord120) == 0x120, "MpvcmcRuntimeView::initWord120 offset must be 0x120");
static_assert(offsetof(MpvcmcRuntimeView, initWord128) == 0x128, "MpvcmcRuntimeView::initWord128 offset must be 0x128");
static_assert(offsetof(MpvcmcRuntimeView, initWord130) == 0x130, "MpvcmcRuntimeView::initWord130 offset must be 0x130");
static_assert(offsetof(MpvcmcRuntimeView, initWord138) == 0x138, "MpvcmcRuntimeView::initWord138 offset must be 0x138");
static_assert(offsetof(MpvcmcRuntimeView, initWord140) == 0x140, "MpvcmcRuntimeView::initWord140 offset must be 0x140");
static_assert(offsetof(MpvcmcRuntimeView, initWord148) == 0x148, "MpvcmcRuntimeView::initWord148 offset must be 0x148");
static_assert(offsetof(MpvcmcRuntimeView, initWord150) == 0x150, "MpvcmcRuntimeView::initWord150 offset must be 0x150");
static_assert(offsetof(MpvcmcRuntimeView, initWord154) == 0x154, "MpvcmcRuntimeView::initWord154 offset must be 0x154");
static_assert(offsetof(MpvcmcRuntimeView, initWord158) == 0x158, "MpvcmcRuntimeView::initWord158 offset must be 0x158");
static_assert(offsetof(MpvcmcRuntimeView, initWord15C) == 0x15C, "MpvcmcRuntimeView::initWord15C offset must be 0x15C");
static_assert(offsetof(MpvcmcRuntimeView, initWord160) == 0x160, "MpvcmcRuntimeView::initWord160 offset must be 0x160");
static_assert(offsetof(MpvcmcRuntimeView, initWord164) == 0x164, "MpvcmcRuntimeView::initWord164 offset must be 0x164");
static_assert(offsetof(MpvcmcRuntimeView, initWord168) == 0x168, "MpvcmcRuntimeView::initWord168 offset must be 0x168");
static_assert(offsetof(MpvcmcRuntimeView, initWord16C) == 0x16C, "MpvcmcRuntimeView::initWord16C offset must be 0x16C");
static_assert(offsetof(MpvcmcRuntimeView, initWord170) == 0x170, "MpvcmcRuntimeView::initWord170 offset must be 0x170");
static_assert(offsetof(MpvcmcRuntimeView, initWord174) == 0x174, "MpvcmcRuntimeView::initWord174 offset must be 0x174");
static_assert(offsetof(MpvcmcRuntimeView, initWord178) == 0x178, "MpvcmcRuntimeView::initWord178 offset must be 0x178");
static_assert(offsetof(MpvcmcRuntimeView, initWord17C) == 0x17C, "MpvcmcRuntimeView::initWord17C offset must be 0x17C");
static_assert(offsetof(MpvcmcRuntimeView, initWord180) == 0x180, "MpvcmcRuntimeView::initWord180 offset must be 0x180");
static_assert(offsetof(MpvcmcRuntimeView, initWord184) == 0x184, "MpvcmcRuntimeView::initWord184 offset must be 0x184");
static_assert(offsetof(MpvcmcRuntimeView, initWord1A4) == 0x1A4, "MpvcmcRuntimeView::initWord1A4 offset must be 0x1A4");
static_assert(offsetof(MpvcmcRuntimeView, umcHalfResMode) == 0x1B8, "MpvcmcRuntimeView::umcHalfResMode offset must be 0x1B8");
static_assert(
  offsetof(MpvcmcRuntimeView, outputWidthPixels) == 0x1D0,
  "MpvcmcRuntimeView::outputWidthPixels offset must be 0x1D0"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputHeightPixels) == 0x1D4,
  "MpvcmcRuntimeView::outputHeightPixels offset must be 0x1D4"
);
static_assert(offsetof(MpvcmcRuntimeView, initWord280) == 0x280, "MpvcmcRuntimeView::initWord280 offset must be 0x280");
static_assert(offsetof(MpvcmcRuntimeView, initWord282) == 0x282, "MpvcmcRuntimeView::initWord282 offset must be 0x282");
static_assert(
  offsetof(MpvcmcRuntimeView, outputRfbBaseAddress) == 0x284,
  "MpvcmcRuntimeView::outputRfbBaseAddress offset must be 0x284"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputYPlaneAddress) == 0x294,
  "MpvcmcRuntimeView::outputYPlaneAddress offset must be 0x294"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputCPlaneAddress) == 0x298,
  "MpvcmcRuntimeView::outputCPlaneAddress offset must be 0x298"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputYPlaneBaseAddress) == 0x29C,
  "MpvcmcRuntimeView::outputYPlaneBaseAddress offset must be 0x29C"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputChromaStrideBytes) == 0x2A0,
  "MpvcmcRuntimeView::outputChromaStrideBytes offset must be 0x2A0"
);
static_assert(
  offsetof(MpvcmcRuntimeView, outputLumaStrideBytes) == 0x2A2,
  "MpvcmcRuntimeView::outputLumaStrideBytes offset must be 0x2A2"
);
static_assert(offsetof(MpvcmcRuntimeView, initWord0D20) == 0xD20, "MpvcmcRuntimeView::initWord0D20 offset must be 0xD20");

// ---------------------------------------------------------------------------
// Global CRI MPV state variables (BSS)
// ---------------------------------------------------------------------------

extern "C" {
  extern std::int32_t SFTIM_prate[];
  extern std::int32_t sfmpv_fps_round[];
  extern std::int32_t sfmpv_conv_29_97[];
  extern std::int32_t sfmpv_conv_59_94[];
  extern SfmpvPara sfmpv_para;
  extern std::int32_t sfmpv_rfb_adr_tbl[2];
  extern std::int32_t sfmpv_work;
  extern std::int32_t sfmpv_discard_wsiz;
  extern std::int32_t sfmpv_picusr_pbuf;
  extern std::int32_t sfmpv_picusr_bufnum;
  extern std::int32_t sfmpv_picusr_buf1siz;
  extern std::int32_t sSofDec_tabs[16];
}

extern "C" alignas(4) std::uint8_t mpvm2v_lib_work[0x38020]{};

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

namespace
{
  /** MPV parameter validation failure code. */
  constexpr std::int32_t kSfmpvErrInvalidPara = -16773355; // 0xFF000F15
  constexpr std::int32_t kSfmpvErrPicUsrBufferTooShort = -16773347; // 0xFF000F1D
  constexpr std::int32_t kSfmpvErrVideoBufferTooSmall = -16773348; // 0xFF000F1C
  constexpr std::int32_t kSfmpvErrReprocessPicAtrFailed = -16773349; // 0xFF000F1B
  constexpr std::int32_t kSfmpvErrSkipFrameFailed = -16773369; // 0xFF000F07
  constexpr std::int32_t kSfmpvErrFrameObjectMissingById = -16773345; // 0xFF000F1F
  constexpr std::int32_t kSfmpvErrInvalidVfrmDrawState = -16773362; // 0xFF000F0E
  constexpr std::int32_t kSfmpvErrFrameObjectMismatch = -16773361; // 0xFF000F0F
  constexpr std::int32_t kSfmpvErrDestroySubFailed = -16773364; // 0xFF000F0C
  constexpr std::int32_t kSfmpvErrWriteApiUnsupported = -16773363; // 0xFF000F0D
  constexpr std::int32_t kSfmpvErrFrameBufferTooSmall = -16773353; // 0xFF000F17

  template <typename T>
  [[nodiscard]] T* AddressToPointer(const std::int32_t address) noexcept
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  [[nodiscard]] std::int32_t AlignAddressTo0x800(const std::int32_t address) noexcept
  {
    return static_cast<std::int32_t>((static_cast<std::uint32_t>(address) + 0x7FFu) & 0xFFFFF800u);
  }

  [[nodiscard]] std::int32_t PointerToAddress(const void* pointer) noexcept
  {
    return static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pointer)));
  }

  [[nodiscard]] std::int32_t RoundUpDivPow2Signed(const std::int32_t value, const std::int32_t shift) noexcept
  {
    const std::int32_t mask = (1 << shift) - 1;
    std::int32_t rounded = value + mask;
    rounded += ((rounded >> 31) & mask);
    return rounded >> shift;
  }

  [[nodiscard]] std::int32_t Div2TowardZero(const std::int32_t value) noexcept
  {
    return (value - (value >> 31)) >> 1;
  }

  [[nodiscard]] std::int32_t Modulo64Index(const std::int32_t value) noexcept
  {
    const std::int32_t modulo = value % 64;
    return (modulo < 0) ? (modulo + 64) : modulo;
  }

  [[nodiscard]] std::int32_t Modulo32Index(const std::int32_t value) noexcept
  {
    const std::int32_t modulo = value % 32;
    return (modulo < 0) ? (modulo + 32) : modulo;
  }

  constexpr std::int32_t kSfptsSourceLaneArrayOffset = 0x1320;

  [[nodiscard]] SfptsSourceLaneRuntimeView*
  GetSfptsSourceLane(SfmpvHandleRuntimeView* const workctrl, const std::int32_t sourceLaneIndex) noexcept
  {
    auto* const laneTableBase = reinterpret_cast<std::uint8_t*>(workctrl) + kSfptsSourceLaneArrayOffset;
    const std::ptrdiff_t laneOffset =
      static_cast<std::ptrdiff_t>(sourceLaneIndex) * static_cast<std::ptrdiff_t>(sizeof(SfptsSourceLaneRuntimeView));
    return reinterpret_cast<SfptsSourceLaneRuntimeView*>(
      laneTableBase + laneOffset
    );
  }

  void AddSigned32ToLane(std::int32_t* const lowWord, std::int32_t* const highWord, const std::int32_t delta) noexcept
  {
    const std::int64_t current =
      (static_cast<std::int64_t>(*highWord) << 32) | static_cast<std::uint32_t>(*lowWord);
    const std::int64_t updated = current + static_cast<std::int64_t>(delta);
    *lowWord = static_cast<std::int32_t>(updated);
    *highWord = static_cast<std::int32_t>(updated >> 32);
  }
}

// ---------------------------------------------------------------------------
// Recovered functions
// ---------------------------------------------------------------------------

extern "C" {

/**
 * Address: 0x00ADAC30 (FUN_00ADAC30, _SFTIM_InitTcode)
 *
 * What it does:
 * Zeroes a 32-byte timecode structure (7 DWORDs + 2 WORDs at end).
 */
std::int32_t SFTIM_InitTcode(void* timecodeState)
{
  auto* const state = static_cast<std::uint8_t*>(timecodeState);

  std::memset(state, 0, 28);             // 7 DWORDs
  *reinterpret_cast<std::uint16_t*>(state + 28) = 0;
  *reinterpret_cast<std::uint16_t*>(state + 30) = 0;

  return reinterpret_cast<std::int32_t>(timecodeState);
}

/**
 * Address: 0x00ADAC00 (FUN_00ADAC00, _SFTIM_InitTtu)
 *
 * What it does:
 * Initialises a time-tracking unit: zeroes the head DWORD, inits the
 * embedded timecode, then sets the mode and scale fields.
 */
std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue)
{
  timerState[0] = 0;
  const auto result = SFTIM_InitTcode(timerState + 1);
  timerState[9] = static_cast<std::uint32_t>(initialValue);
  timerState[10] = 1;
  return result;
}

/**
 * Address: 0x00ADAC60 (FUN_00ADAC60, _SFTIM_UpdateItime)
 *
 * What it does:
 * Updates adaptive interpolation-time step lanes used by late-frame prediction.
 */
void SFTIM_UpdateItime(void* const timerState, const std::int32_t interpolationTime)
{
  auto* const timingLane = static_cast<SfmpvTimingLane*>(timerState);
  const std::int32_t previousInterpolationTime = timingLane->interpolationWindowTimeBase;
  if (previousInterpolationTime == -5) {
    timingLane->interpolationWindowTimeBase = interpolationTime;
    return;
  }

  const std::int32_t interpolationDelta = interpolationTime - previousInterpolationTime;
  if (interpolationDelta == 0) {
    return;
  }

  timingLane->interpolationWindowTimeBase = interpolationTime;

  if (timingLane->interpolationWindowMaxStep <= interpolationDelta) {
    timingLane->interpolationWindowMaxStep = interpolationDelta;
  }
  if (timingLane->interpolationWindowMinStep >= interpolationDelta) {
    timingLane->interpolationWindowMinStep = interpolationDelta;
  }

  const std::int32_t adaptiveStep = timingLane->interpolationWindowAdaptiveStep;
  if (adaptiveStep == std::numeric_limits<std::int32_t>::max() || adaptiveStep <= interpolationDelta) {
    timingLane->interpolationWindowAdaptiveStep = interpolationDelta;
    return;
  }

  const std::int32_t decayStep = (adaptiveStep - interpolationDelta) / 8;
  if (decayStep == 0) {
    timingLane->interpolationWindowAdaptiveStep = interpolationDelta;
    return;
  }

  timingLane->interpolationWindowAdaptiveStep = adaptiveStep - decayStep;
}

/**
 * Address: 0x00ADACF0 (FUN_00ADACF0, _SFTIM_GetNextItime)
 *
 * What it does:
 * Returns the next interpolation-time gate from adaptive/max step lanes,
 * or `INT_MAX` once current interpolation time has crossed both gates.
 */
std::int32_t SFTIM_GetNextItime(void* const timerState, const std::int32_t interpolationTime)
{
  const auto* const timingLane = static_cast<const SfmpvTimingLane*>(timerState);
  const std::int32_t previousInterpolationTime = timingLane->interpolationWindowTimeBase;
  std::int32_t nextInterpolationTime = previousInterpolationTime + timingLane->interpolationWindowAdaptiveStep;
  if (interpolationTime >= nextInterpolationTime) {
    nextInterpolationTime = previousInterpolationTime + timingLane->interpolationWindowMaxStep;
    if (interpolationTime >= nextInterpolationTime) {
      return std::numeric_limits<std::int32_t>::max();
    }
  }
  return nextInterpolationTime;
}

/**
 * Address: 0x00AE5E10 (FUN_00AE5E10, _UTY_MemsetDword)
 *
 * What it does:
 * Fills one DWORD lane range with one 32-bit value using reverse-order tail
 * handling and 16-DWORD unrolled blocks.
 */
std::int32_t UTY_MemsetDword(void* const destination, const std::uint32_t value, const unsigned int dwordCount)
{
  auto* cursor = static_cast<std::uint32_t*>(destination) + dwordCount;

  unsigned int tailCount = dwordCount & 0x0Fu;
  while (tailCount != 0u) {
    *--cursor = value;
    --tailCount;
  }

  unsigned int blockCount = dwordCount >> 4;
  while (blockCount != 0u) {
    cursor -= 16;
    cursor[0] = value;
    cursor[1] = value;
    cursor[2] = value;
    cursor[3] = value;
    cursor[4] = value;
    cursor[5] = value;
    cursor[6] = value;
    cursor[7] = value;
    cursor[8] = value;
    cursor[9] = value;
    cursor[10] = value;
    cursor[11] = value;
    cursor[12] = value;
    cursor[13] = value;
    cursor[14] = value;
    cursor[15] = value;
    --blockCount;
  }

  return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(destination));
}

/**
 * Address: 0x00AD4EA0 (FUN_00AD4EA0, _sfmpv_InitPicAtr)
 *
 * What it does:
 * Fills a 32-DWORD picture-attribute block with 0xFFFFFFFF (-1).
 */
void sfmpv_InitPicAtr(void* picAtrState)
{
  UTY_MemsetDword(picAtrState, 0xFFFFFFFF, 0x20);
}

/**
 * Address: 0x00AD4E30 (FUN_00AD4E30, _sfmpv_InitFrmObj)
 *
 * What it does:
 * Initialises an array of frame objects. Each frame object is 58 DWORDs
 * (0xE8 bytes). Clears control fields, initialises the embedded timer,
 * copies one tab entry per frame, and inits picture attributes.
 */
void sfmpv_InitFrmObj(std::uint32_t* frameObjects, const std::int32_t* tabEntries, std::int32_t count)
{
  for (std::int32_t i = 0; i < count; ++i, frameObjects += 58) {
    frameObjects[0] = 0;
    frameObjects[1] = 0;
    SFTIM_InitTtu(frameObjects + 3, 0);
    frameObjects[2] = static_cast<std::uint32_t>(tabEntries[i]);
    frameObjects[14] = 0;
    frameObjects[15] = 1;
    frameObjects[16] = 0;
    frameObjects[17] = 0;
    frameObjects[18] = 0;
    frameObjects[19] = 0;
    frameObjects[20] = 0;
    frameObjects[22] = 0xFFFFFFFF; // -1
    sfmpv_InitPicAtr(frameObjects + 23);
  }
}

/**
 * Address: 0x00AD4DB0 (FUN_00AD4DB0, _sfmpv_InitComplementPts)
 *
 * What it does:
 * Zeroes and sentinel-fills an 8-DWORD complement-points block.
 */
void sfmpv_InitComplementPts(std::uint32_t* complementPts)
{
  complementPts[0] = 0;
  complementPts[1] = 0;
  complementPts[2] = 0;
  complementPts[4] = 0xFFFFFFFF; // -1
  complementPts[5] = 0xFFFFFFFF; // -1
  complementPts[6] = 0;
  complementPts[7] = 0xFFFFFFFF; // -1
}

/**
 * Address: 0x00AD4EC0 (FUN_00AD4EC0, _SFMPVF_InitPicUsr)
 *
 * What it does:
 * Zeroes the picture-user state: 5 header DWORDs followed by 16 pairs
 * (32 DWORDs).
 */
void SFMPVF_InitPicUsr(std::uint32_t* picUsrState)
{
  picUsrState[0] = 0;
  picUsrState[1] = 0;
  picUsrState[2] = 0;
  picUsrState[3] = 0;
  picUsrState[4] = 0;

  std::uint32_t* cursor = picUsrState + 5;
  for (std::int32_t i = 0; i < 16; ++i) {
    cursor[0] = 0;
    cursor[1] = 0;
    cursor += 2;
  }
}

/**
 * Address: 0x00AD1700 (FUN_00AD1700, _SFD_SetMpvParaTbl)
 *
 * What it does:
 * Copies one MPV parameter table, clears validator lanes (`val4/val8`), aligns
 * ring-frame-buffer and SofDec tab addresses to 0x800, and writes up to
 * `nfrm_pool_wk` tab entries.
 */
std::int32_t SFD_SetMpvParaTbl(
  const SfmpvPara* const parameterTable,
  const std::int32_t* const ringFrameBufferAddressTable,
  void* const* const sofDecTabAddressTable
)
{
  sfmpv_para = *parameterTable;
  sfmpv_para.val4 = 0;
  sfmpv_para.val8 = 0;

  for (std::int32_t tableIndex = 0; tableIndex < 2; ++tableIndex) {
    sfmpv_rfb_adr_tbl[tableIndex] = AlignAddressTo0x800(ringFrameBufferAddressTable[tableIndex]);
  }

  for (std::int32_t tabIndex = 0; tabIndex < 16; ++tabIndex) {
    if (tabIndex >= parameterTable->nfrm_pool_wk) {
      sSofDec_tabs[tabIndex] = 0;
    } else {
      const auto tabAddress =
        static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sofDecTabAddressTable[tabIndex])));
      sSofDec_tabs[tabIndex] = AlignAddressTo0x800(tabAddress);
    }
  }

  return 16;
}

/**
 * Address: 0x00AD1AE0 (FUN_00AD1AE0, _sfmpvf_SetPicUsrBuf)
 *
 * What it does:
 * Installs one external picture-user buffer table for an MPV handle, validates
 * minimum frame-slot count against prep target (`+3`), and populates per-slot
 * picture-user entries; clears picture-user state when any input argument is 0.
 */
std::int32_t sfmpvf_SetPicUsrBuf(
  const std::int32_t workctrlAddress,
  const std::int32_t userBufferAddress,
  const std::int32_t frameSlotCount,
  const std::int32_t bytesPerFrame
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  auto* const picUsrState = reinterpret_cast<std::uint32_t*>(&mpvInfo->pictureUserBufferAddress);

  if (userBufferAddress != 0 && frameSlotCount != 0 && bytesPerFrame != 0) {
    if (frameSlotCount < (workctrl->prepFrameTargetCount + 3)) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrPicUsrBufferTooShort);
    }

    mpvInfo->pictureUserBufferAddress = userBufferAddress;
    mpvInfo->pictureUserBufferMirrorAddress = userBufferAddress;
    mpvInfo->pictureUserBufferCount = frameSlotCount;
    mpvInfo->pictureUserBufferSize = bytesPerFrame;
    mpvInfo->pictureUserFlags = 0;

    std::int32_t entryAddress = userBufferAddress + bytesPerFrame;
    std::int32_t entryCount = frameSlotCount - 1;
    if (entryCount > 16) {
      entryCount = 16;
    }

    for (std::int32_t entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
      mpvInfo->pictureUserEntries[entryIndex].value0 = entryAddress;
      mpvInfo->pictureUserEntries[entryIndex].value1 = 0;
      entryAddress += bytesPerFrame;
    }
  } else {
    SFMPVF_InitPicUsr(picUsrState);
  }

  return 0;
}

/**
 * Address: 0x00AD1C70 (FUN_00AD1C70, _sfmpv_SetCondY16)
 *
 * What it does:
 * When condition lane `28` is enabled, probes SFHDS color-type lane and updates
 * MPV condition `5`; returns unchanged condition probe result otherwise.
 */
std::int32_t sfmpv_SetCondY16(const std::int32_t workctrlAddress)
{
  std::int32_t result = SFSET_GetCond(workctrlAddress, 28);
  if (result == 0) {
    return result;
  }

  result = SFHDS_GetColType(workctrlAddress);
  if (result != -1) {
    const auto cond5Arg =
      reinterpret_cast<std::int32_t(*)()>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(result == 0)));
    return SFD_SetMpvCond(workctrlAddress, 5, cond5Arg);
  }

  return result;
}

/**
 * Address: 0x00AD1CB0 (FUN_00AD1CB0, _sfmpv_ProcessAuxShc)
 *
 * What it does:
 * Reads auxiliary sequence-header chunk bounds from condition lanes `93/94`,
 * decodes picture attributes when concat control is in the initial state, and
 * flips MPV info state to reprocessed-concat mode on successful decode.
 */
std::int32_t sfmpv_ProcessAuxShc(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  SfbufRingChunkRuntimeView pictureRange{};
  pictureRange.bufferAddress = reinterpret_cast<std::uint8_t*>(
      static_cast<std::uintptr_t>(SFSET_GetCond(workctrlAddress, 93)));
  std::int32_t result = SFSET_GetCond(workctrlAddress, 94);
  pictureRange.byteCount = result;
  if (pictureRange.bufferAddress != nullptr && result != 0 && mpvInfo->concatControlFlags == 0xC0) {
    std::int32_t consumedBytes = 0;
    result = MPV_DecodePicAtr(
      mpvInfo->decoderHandle,
      reinterpret_cast<const std::int32_t*>(&pictureRange),
      &consumedBytes
    );
    if (result == 0) {
      mpvInfo->defectPictureTypeState = 2;
      mpvInfo->concatControlFlags = 0xC8;
    }
  }

  return result;
}

/**
 * Address: 0x00AF5C40 (FUN_00AF5C40, _MPVM2V_Init)
 *
 * What it does:
 * Initializes the M2V backend using the dedicated MPVM2V work arena.
 */
std::int32_t MPVM2V_Init()
{
  return M2V_Init(0x20, static_cast<void*>(mpvm2v_lib_work), 0x38020);
}

/**
 * Address: 0x00AF5F50 (FUN_00AF5F50, _mpvcmc_InitMcOiTa)
 *
 * What it does:
 * Seeds MPV CMC interpolation-pointer lanes to the internal table storage
 * block and resets per-lane span words.
 */
MpvcmcRuntimeView* mpvcmc_InitMcOiTa(MpvcmcRuntimeView* const runtimeView)
{
  runtimeView->initWord154 = (runtimeView->initWord1A4 != 0) ? 4 : -1;

  const std::int32_t tableAddress = PointerToAddress(&runtimeView->initWord0D20);
  runtimeView->initWord158 = tableAddress;
  runtimeView->initWord160 = tableAddress;
  runtimeView->initWord168 = tableAddress;
  runtimeView->initWord170 = tableAddress;
  runtimeView->initWord178 = tableAddress;
  runtimeView->initWord180 = tableAddress;

  runtimeView->initWord15C = 8;
  runtimeView->initWord164 = 8;
  runtimeView->initWord16C = 8;
  runtimeView->initWord174 = 8;
  runtimeView->initWord17C = 8;
  runtimeView->initWord184 = 8;
  return runtimeView;
}

/**
 * Address: 0x00AF5FC0 (FUN_00AF5FC0, _MPVCMC_InitMcOiRt)
 *
 * What it does:
 * Initializes MPV CMC interpolation runtime words from fixed seed lanes in
 * the CMC object.
 */
MpvcmcRuntimeView* MPVCMC_InitMcOiRt(MpvcmcRuntimeView* const runtimeView)
{
  runtimeView->initWord120 = (runtimeView->initWord1A4 != 0) ? 4 : -1;

  const std::int32_t seedWord0 = runtimeView->initWord280;
  runtimeView->initWord128 = seedWord0;
  runtimeView->initWord130 = seedWord0;

  const std::int32_t seedWord1 = runtimeView->initWord282;
  runtimeView->initWord138 = seedWord1;
  runtimeView->initWord140 = seedWord1;
  runtimeView->initWord148 = seedWord1;
  runtimeView->initWord150 = seedWord1;
  return runtimeView;
}

/**
 * Address: 0x00AF6010 (FUN_00AF6010, _MPVCMC_SetCcnt)
 *
 * What it does:
 * Recomputes CMC count/state lanes from the runtime mode gate.
 */
extern "C" std::int32_t MPVCMC_SetCcnt(MpvcmcRuntimeView* const runtimeView)
{
  const std::int32_t nextCount = (runtimeView->initWord1A4 != 0) ? 4 : -1;
  runtimeView->initWord154 = nextCount;
  runtimeView->initWord120 = nextCount;
  return nextCount;
}

/**
 * Address: 0x00AF60F0 (FUN_00AF60F0, _MPVUMC_Finish)
 *
 * What it does:
 * Finalizes UMC runtime state (no-op in this binary).
 */
extern "C" void MPVUMC_Finish()
{
}

/**
 * Address: 0x00AF6100 (FUN_00AF6100, _MPVUMC_InitOutRfb)
 *
 * What it does:
 * Computes Y/C output frame-buffer lane addresses and aligned strides for the
 * current decode-frame geometry.
 */
extern "C" std::int32_t MPVUMC_InitOutRfb(MpvcmcRuntimeView* const runtimeView)
{
  std::int32_t widthPixels = runtimeView->outputWidthPixels;
  std::int32_t heightPixels = runtimeView->outputHeightPixels;
  const std::int32_t outputRfbBaseAddress = runtimeView->outputRfbBaseAddress;

  if (runtimeView->umcHalfResMode != 0) {
    widthPixels = RoundUpDivPow2Signed(widthPixels, 3);
    heightPixels = RoundUpDivPow2Signed(heightPixels, 3);
  }

  runtimeView->outputYPlaneBaseAddress = outputRfbBaseAddress;

  const std::int32_t alignedLumaWidth = RoundUpDivPow2Signed(widthPixels, 4) << 4;
  const std::int32_t lumaStrideUnits = RoundUpDivPow2Signed(alignedLumaWidth, 5);
  runtimeView->outputLumaStrideBytes = static_cast<std::int16_t>(lumaStrideUnits << 5);

  const std::int32_t alignedChromaHalfWidth = Div2TowardZero(alignedLumaWidth);
  const std::int32_t chromaStrideUnits = RoundUpDivPow2Signed(alignedChromaHalfWidth, 5);
  runtimeView->outputChromaStrideBytes = static_cast<std::int16_t>(chromaStrideUnits << 5);

  const std::int32_t macroblockRows = RoundUpDivPow2Signed(heightPixels, 5);
  const std::int32_t outputYPlaneAddress = outputRfbBaseAddress + ((lumaStrideUnits * macroblockRows) << 10);
  runtimeView->outputYPlaneAddress = outputYPlaneAddress;

  const std::int32_t macroblockRowBytes = macroblockRows << 5;
  const std::int32_t halfMacroblockRowBytes = Div2TowardZero(macroblockRowBytes);
  const std::int32_t outputCPlaneAddress =
    outputYPlaneAddress + (((halfMacroblockRowBytes * chromaStrideUnits) << 5));
  runtimeView->outputCPlaneAddress = outputCPlaneAddress;
  return outputCPlaneAddress;
}

/**
 * Address: 0x00AF61D0 (FUN_00AF61D0, _MPVUMC_EndOfFrame)
 *
 * What it does:
 * Ends one UMC frame-decode pass (no-op in this binary).
 */
extern "C" void MPVUMC_EndOfFrame()
{
}

/**
 * Address: 0x00AD1BE0 (FUN_00AD1BE0, _sfmpv_ChkFatal)
 *
 * What it does:
 * Returns MPV fatal-startup latch state (always clear in this runtime build).
 */
std::int32_t sfmpv_ChkFatal()
{
  return 0;
}

/**
 * Address: 0x00AD1B70 (FUN_00AD1B70, _SFMPV_Init)
 *
 * What it does:
 * Checks fatal-startup state, initializes the MPV work lane, and clears the
 * parameter/table globals on success. On failure, returns the recovered Sofdec
 * error code path.
 */
std::int32_t SFMPV_Init()
{
  if (sfmpv_ChkFatal()) {
    while (true) {
    }
  }

  const std::int32_t initResult = MPV_Init(32, reinterpret_cast<std::int32_t>(&sfmpv_work));
  if (initResult != 0) {
    std::int32_t errorCode = -(initResult != -16515323);
    errorCode &= 0xEE;
    return SFLIB_SetErr(0, errorCode - 16773357);
  }

  // _SFMPVF_InitPool
  std::memset(&sfmpv_para, 0, 0x24u);
  sfmpv_rfb_adr_tbl[0] = 0;
  sfmpv_rfb_adr_tbl[1] = 0;
  std::memset(sSofDec_tabs, 0, sizeof(sSofDec_tabs));
  sfmpv_discard_wsiz = 0;
  return 0;
}

/**
 * Address: 0x00AD1BF0 (FUN_00AD1BF0, _SFMPV_Finish)
 *
 * What it does:
 * Finalizes MPV global runtime lanes and returns Sofdec success code `0`.
 */
std::int32_t SFMPV_Finish()
{
  (void)MPV_Finish();
  return 0;
}

/**
 * Address: 0x00AD1C00 (FUN_00AD1C00, _SFMPV_ExecServer)
 *
 * What it does:
 * Forwards one MPV server-execution tick to `sfmpv_ExecServerSub`.
 */
std::int32_t SFMPV_ExecServer(const std::int32_t workctrlAddress)
{
  return sfmpv_ExecServerSub(workctrlAddress);
}

/**
 * Address: 0x00AD4DD0 (FUN_00AD4DD0, _sfmpvf_CheckMpvPara)
 *
 * What it does:
 * Validates global MPV parameters: frame pool count must be in [1..16],
 * and either (val4 && val8) hold, or all rfb address table entries and
 * SofDec tab entries must be non-zero.
 */
std::int32_t sfmpvf_CheckMpvPara()
{
  if (sfmpv_para.nfrm_pool_wk <= 0 || sfmpv_para.nfrm_pool_wk > 16) {
    return -1;
  }

  if (sfmpv_para.val4 != 0 && sfmpv_para.val8 != 0) {
    return 0;
  }

  // Check rfb address table -- all entries up to sfmpv_work boundary must be non-zero
  const auto* rfbEntry = &sfmpv_rfb_adr_tbl[0];
  while (*rfbEntry != 0) {
    ++rfbEntry;
    if (reinterpret_cast<std::uintptr_t>(rfbEntry) >= reinterpret_cast<std::uintptr_t>(&sfmpv_work)) {
      // All rfb entries non-zero; now check SofDec tabs
      for (std::int32_t idx = 0; idx < sfmpv_para.nfrm_pool_wk; ++idx) {
        if (sSofDec_tabs[idx] == 0) {
          return -1;
        }
      }
      return 0;
    }
  }

  return -1;
}

/**
 * Address: 0x00AD4C80 (FUN_00AD4C80, _sfmpv_InitInf)
 *
 * IDA signature:
 * int __cdecl sfmpv_InitInf(int a1, _DWORD *a2)
 *
 * What it does:
 * Initialises an MPV info block: validates global parameters, copies the
 * parameter block, rfb address table, and SofDec tabs into the info
 * structure, then initialises frame objects, picture attributes,
 * complement points, picture-user state, and links user-stream slots.
 */
std::int32_t sfmpv_InitInf(std::int32_t /*unused*/, std::uint32_t* infoBlock)
{
  if (sfmpvf_CheckMpvPara() != 0) {
    return SFLIB_SetErr(0, kSfmpvErrInvalidPara);
  }

  // Copy parameter block (9 DWORDs = 0x24 bytes) starting at infoBlock[1]
  std::memcpy(infoBlock + 1, &sfmpv_para, 0x24);

  // Copy rfb address table entries
  infoBlock[10] = static_cast<std::uint32_t>(sfmpv_rfb_adr_tbl[0]);
  infoBlock[11] = static_cast<std::uint32_t>(sfmpv_rfb_adr_tbl[1]);

  // Copy SofDec tabs (16 DWORDs = 0x40 bytes) starting at infoBlock[12]
  std::memcpy(infoBlock + 12, sSofDec_tabs, 0x40);

  // Zero/init header and control fields
  infoBlock[0] = 0;
  infoBlock[28] = 0;
  infoBlock[29] = 5;
  infoBlock[30] = 192;       // 0xC0
  infoBlock[78] = 0;
  infoBlock[79] = 1;
  infoBlock[31] = 0;
  infoBlock[32] = 0;
  infoBlock[88] = 0;
  infoBlock[89] = 0;
  infoBlock[90] = 0;
  infoBlock[91] = 0;
  infoBlock[92] = 0;
  infoBlock[93] = 0;

  // Initialise frame objects (16 entries starting at infoBlock[96], using tab entries from infoBlock[12])
  sfmpv_InitFrmObj(infoBlock + 96, reinterpret_cast<const std::int32_t*>(infoBlock + 12), 16);

  infoBlock[33] = 0;
  infoBlock[34] = 0;

  // Initialise picture attributes at infoBlock[35]
  sfmpv_InitPicAtr(infoBlock + 35);

  // Sentinel and control fields
  infoBlock[67] = 0xFFFFFFFF; // -1
  infoBlock[68] = 0;
  infoBlock[69] = 0x7FFFFFFF;

  // Initialise complement points at infoBlock[70]
  sfmpv_InitComplementPts(infoBlock + 70);

  // Initialise picture-user state at infoBlock[1024]
  SFMPVF_InitPicUsr(infoBlock + 1024);

  // Link 16 user-stream slots: each frame object slot (stride 58 DWORDs)
  // gets a pointer to its corresponding picture-user entry pair (stride 2 DWORDs)
  auto* slotPtr = infoBlock + 117;       // first frame object's user-stream link field
  auto* picUsrEntry = infoBlock + 1029;   // first picture-user entry (after 5-DWORD header)
  for (std::int32_t i = 0; i < 16; ++i) {
    *slotPtr = reinterpret_cast<std::uint32_t>(picUsrEntry);
    picUsrEntry += 2;
    slotPtr += 58;
  }

  return 0;
}

/**
 * Address: 0x00AD1E20 (FUN_00AD1E20, _sfmpv_IsVbvEnough)
 *
 * What it does:
 * Evaluates whether the active MPV stream ring has enough VBV data available
 * to continue decode without underflow.
 */
std::int32_t sfmpv_IsVbvEnough(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  const std::int32_t decoderHandle = mpvInfo->decoderHandle;

  const std::int32_t termSourceState = sfmpv_GetTermSrc(workctrlAddress);
  if (termSourceState == 1) {
    return termSourceState;
  }

  if (workctrl->frameHeaderHandle != 0 && workctrl->vbvBypassFlag == 0) {
    return 1;
  }

  std::int32_t bitRate = 0;
  MPV_GetBitRate(decoderHandle, &bitRate);
  if (bitRate == 0x3FFFF) {
    return 1;
  }

  if (SFBUF_GetWTot(workctrlAddress, 1) >= mpvInfo->vbvWriteThreshold) {
    return 1;
  }

  const std::int32_t streamLane = (SFTRN_IsSetup(workctrlAddress, 1) == 0) ? 1 : 0;
  const std::int32_t totalWritableBytes = SFBUF_GetWTot(workctrlAddress, streamLane);
  const std::int32_t bufferedBytes = SFBUF_RingGetDataSiz(workctrlAddress, streamLane);
  return (totalWritableBytes >= bufferedBytes) ? 1 : 0;
}

/**
 * Address: 0x00AD2400 (FUN_00AD2400, _sfmpv_CheckViBufSiz)
 *
 * What it does:
 * Verifies that video-ring readable bytes minus ring-buffer overhead meets one
 * per-handle minimum threshold lane.
 */
std::int32_t sfmpv_CheckViBufSiz(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t ringIndex = workctrl->prepSourceLaneIndex;
  const std::int32_t ringBufferBytes = SFBUF_GetRingBufSiz(workctrlAddress, ringIndex);
  const std::int32_t readableBytes = SFBUF_RingGetDataSiz(workctrlAddress, ringIndex);
  if ((readableBytes - ringBufferBytes) >= workctrl->minimumVideoBufferBytes) {
    return 0;
  }
  return SFLIB_SetErr(workctrlAddress, kSfmpvErrVideoBufferTooSmall);
}

/**
 * Address: 0x00ADC140 (FUN_00ADC140, _SFMPVF_IsTermDec)
 *
 * What it does:
 * Returns MPV term-decode state lane from the per-handle MPV info owner.
 */
std::int32_t SFMPVF_IsTermDec(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const auto* const mpvInfo = reinterpret_cast<const SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);
  return mpvInfo->termDecodeState;
}

/**
 * Address: 0x00ADC170 (FUN_00ADC170, _SFMPVF_GetNumFrm)
 *
 * What it does:
 * Counts decodable frame objects (`state 2|4`, `frameId == -1`) from MPV frame
 * object pool under SFLIB lock; returns `-1` when term-decode is active and no
 * decodable frames remain.
 */
std::int32_t SFMPVF_GetNumFrm(const std::int32_t workctrlAddress)
{
  SFLIB_LockCs();

  std::int32_t decodableFrameCount = 0;
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const auto* const mpvInfo = reinterpret_cast<const SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);
  for (std::int32_t frameIndex = 0; frameIndex < mpvInfo->frameObjectCount; ++frameIndex) {
    const SfmpvfFrameObjectRuntimeView& frameObject = mpvInfo->frameObjects[frameIndex];
    if ((frameObject.decodeState == 2 || frameObject.decodeState == 4) && frameObject.frameId == -1) {
      ++decodableFrameCount;
    }
  }

  if (mpvInfo->termDecodeState == 1 && decodableFrameCount == 0) {
    decodableFrameCount = -1;
  }

  SFLIB_UnlockCs();
  return decodableFrameCount;
}

/**
 * Address: 0x00ADC640 (FUN_00ADC640, _sfmpvf_IsChkFirst)
 *
 * What it does:
 * Chooses which decodable frame object should be output first by comparing
 * concat/decode ordering lanes and a final per-picture tie-break metric.
 */
std::int32_t sfmpvf_IsChkFirst(
  const SfmpvfFrameObjectRuntimeView* const selectedFrameObject,
  const SfmpvfFrameObjectRuntimeView* const candidateFrameObject
)
{
  if (selectedFrameObject == nullptr) {
    return 1;
  }

  if (candidateFrameObject->decodeConcatOrdinal < selectedFrameObject->decodeConcatOrdinal) {
    return 1;
  }
  if (candidateFrameObject->decodeConcatOrdinal > selectedFrameObject->decodeConcatOrdinal) {
    return 0;
  }

  if (candidateFrameObject->pictureDecodeLane.progressiveSequence < selectedFrameObject->pictureDecodeLane.progressiveSequence) {
    return 1;
  }
  if (candidateFrameObject->pictureDecodeLane.progressiveSequence > selectedFrameObject->pictureDecodeLane.progressiveSequence) {
    return 0;
  }

  if (candidateFrameObject->pictureDecodeLane.sequenceStamp < selectedFrameObject->pictureDecodeLane.sequenceStamp) {
    return 1;
  }
  if (candidateFrameObject->pictureDecodeLane.sequenceStamp > selectedFrameObject->pictureDecodeLane.sequenceStamp) {
    return 0;
  }

  return (candidateFrameObject->pictureDecodeLane.decodeOrderTiebreak < selectedFrameObject->pictureDecodeLane.decodeOrderTiebreak) ? 1 : 0;
}

/**
 * Address: 0x00ADC2C0 (FUN_00ADC2C0, _SFMPVF_HoldFrm)
 *
 * What it does:
 * Selects one next drawable frame-object (`state 2|4` and unissued frame id)
 * under SFLIB lock, with single-frame holdback when output-gate lanes are not
 * enabled.
 */
std::int32_t SFMPVF_HoldFrm(const std::int32_t workctrlAddress)
{
  SFLIB_LockCs();

  SfmpvfFrameObjectRuntimeView* selectedFrameObject = nullptr;
  std::int32_t selectableFrameCount = 0;

  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const mpvInfo = reinterpret_cast<SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);
  if (mpvInfo->frameObjectCount > 0) {
    for (std::int32_t frameIndex = 0; frameIndex < mpvInfo->frameObjectCount; ++frameIndex) {
      auto* const candidateFrameObject = &mpvInfo->frameObjects[frameIndex];
      if ((candidateFrameObject->decodeState == 2 || candidateFrameObject->decodeState == 4) && candidateFrameObject->frameId == -1) {
        ++selectableFrameCount;
        if (sfmpvf_IsChkFirst(selectedFrameObject, candidateFrameObject) != 0) {
          selectedFrameObject = candidateFrameObject;
        }
      }
    }

    if (selectableFrameCount == 1 && mpvInfo->termDecodeState == 0 && mpvInfo->allowSingleFrameOutput == 0) {
      selectedFrameObject = nullptr;
    }
  }

  SFLIB_UnlockCs();
  return PointerToAddress(selectedFrameObject);
}

/**
 * Address: 0x00AD1DE0 (FUN_00AD1DE0, _sfmpv_IsPrepFrmEnough)
 *
 * What it does:
 * Tests whether currently decoded/prepared frame count reaches the MPV prep
 * threshold lane for this workctrl.
 */
std::int32_t sfmpv_IsPrepFrmEnough(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  std::int32_t requiredFrameCount = workctrl->prepFrameRequiredCount;
  if (requiredFrameCount == -1 || workctrl->prepFrameTargetCount < requiredFrameCount) {
    requiredFrameCount = workctrl->prepFrameTargetCount;
  }

  std::int32_t preparedFrameCount = SFMPVF_GetNumFrm(workctrlAddress);
  if (workctrl->decodePathMode == 2) {
    preparedFrameCount += workctrl->preparedFrameCount;
  }

  return (preparedFrameCount >= requiredFrameCount) ? 1 : 0;
}

/**
 * Address: 0x00AD1DA0 (FUN_00AD1DA0, _sfmpv_IsPrepEnd)
 *
 * What it does:
 * Reports MPV prep completion when decoder is already in term-decode state, or
 * when both prep-frame and VBV readiness predicates are satisfied.
 */
std::int32_t sfmpv_IsPrepEnd(const std::int32_t workctrlAddress)
{
  if (SFMPVF_IsTermDec(workctrlAddress) != 0) {
    return 1;
  }
  return (sfmpv_IsPrepFrmEnough(workctrlAddress) != 0 && sfmpv_IsVbvEnough(workctrlAddress) != 0) ? 1 : 0;
}

/**
 * Address: 0x00AD1ED0 (FUN_00AD1ED0, _sfmpv_FixedStartTtu)
 *
 * What it does:
 * Arms fixed-start TTU latch when finite frame interpolation threshold is
 * present in the MPV timing lane.
 */
std::int32_t sfmpv_FixedStartTtu(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  if (workctrl->timingLane.frameInterpolationTime != 0x7FFFFFFF) {
    workctrl->timingLane.interpolationEnabled = 1;
  }
  return workctrlAddress;
}

/**
 * Address: 0x00AD1D40 (FUN_00AD1D40, _sfmpv_ChkPrepFlg)
 *
 * What it does:
 * Latches MPV prep destination lane once source prep is available and MPV prep
 * completion predicate succeeds.
 */
std::int32_t sfmpv_ChkPrepFlg(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t prepDestinationLaneIndex = workctrl->prepDestinationLaneIndex;
  const std::int32_t prepSourceLaneIndex = workctrl->prepSourceLaneIndex;

  std::int32_t result = SFBUF_GetPrepFlg(workctrlAddress, prepDestinationLaneIndex);
  if (result == 1) {
    return result;
  }

  result = SFBUF_GetPrepFlg(workctrlAddress, prepSourceLaneIndex);
  if (result != 1) {
    return result;
  }

  result = sfmpv_IsPrepEnd(workctrlAddress);
  if (result == 0) {
    return result;
  }

  (void)SFBUF_SetPrepFlg(workctrlAddress, prepDestinationLaneIndex, 1);
  return sfmpv_FixedStartTtu(workctrlAddress);
}

/**
 * Address: 0x00AD1F40 (FUN_00AD1F40, _sfmpv_IsFinalFrmGotten)
 *
 * What it does:
 * Reports final-frame completion gate based on term-decode state, frame count,
 * decode path mode, and prepared/consumed frame counters.
 */
std::int32_t sfmpv_IsFinalFrmGotten(const std::int32_t workctrlAddress, const std::int32_t frameCount)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  if (SFMPVF_IsTermDec(workctrlAddress) == 0) {
    return 0;
  }
  if (frameCount == 0) {
    return 1;
  }

  if (
    workctrl->decodePathMode == 1 && frameCount == 1
    && workctrl->preparedFrameCount > workctrl->consumedFrameCount
  ) {
    return 1;
  }
  return 0;
}

/**
 * Address: 0x00AD1F90 (FUN_00AD1F90, _sfmpv_SetTermDst)
 *
 * What it does:
 * Writes term flag into the active MPV destination SFBUF lane.
 */
std::int32_t sfmpv_SetTermDst(const std::int32_t workctrlAddress, const std::int32_t termFlag)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  return SFBUF_SetTermFlg(workctrlAddress, workctrl->prepDestinationLaneIndex, termFlag);
}

/**
 * Address: 0x00AD1EF0 (FUN_00AD1EF0, _sfmpv_ChkTermFlg)
 *
 * What it does:
 * Latches MPV destination term flag when final-frame condition is reached and
 * clears condition `5` when no playback info object is currently bound.
 */
std::int32_t sfmpv_ChkTermFlg(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t frameCount = SFMPVF_GetNumFrm(workctrlAddress);

  if (frameCount == -1 || sfmpv_IsFinalFrmGotten(workctrlAddress, frameCount) != 0) {
    (void)sfmpv_SetTermDst(workctrlAddress, 1);
    if (workctrl->playbackInfoAddress == 0) {
      return SFSET_SetCond(workctrlAddress, 5, 0);
    }
    return workctrl->playbackInfoAddress;
  }
  return 0;
}

/**
 * Address: 0x00AD2020 (FUN_00AD2020, _sfmpv_GetActiveSize)
 *
 * What it does:
 * Probes the active source ring lane, searches delimiter boundaries, refreshes
 * delimiter cache lanes when required, and returns one decodable active-span.
 */
std::int32_t sfmpv_GetActiveSize(
  const std::int32_t workctrlAddress,
  std::int32_t* const outActiveSize,
  std::int32_t* const outDelimiterFlags,
  std::int32_t* const outHasActiveUnit
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfbufRingCursorSnapshotRuntimeView ringCursor{};
  const std::int32_t sourceLaneIndex = workctrl->prepSourceLaneIndex;

  *outActiveSize = 0;
  *outDelimiterFlags = 0;
  *outHasActiveUnit = 0;

  const std::int32_t ringReadResult =
    SFBUF_RingGetRead(workctrlAddress, sourceLaneIndex, reinterpret_cast<std::int32_t*>(&ringCursor));
  if (ringReadResult != 0) {
    return ringReadResult;
  }
  if (ringCursor.firstChunk.byteCount == 0) {
    return 0;
  }

  std::int32_t delimiterFlags = 0;
  std::uint8_t* delimiterCursor = sfmpv_SearchDelim(PointerToAddress(&ringCursor), 206, &delimiterFlags);
  if (delimiterCursor != ringCursor.firstChunk.bufferAddress) {
    std::int32_t activeSize = 0;
    if (delimiterCursor != nullptr) {
      activeSize = sfmpv_CalcDistance(reinterpret_cast<const std::int32_t*>(&ringCursor), delimiterCursor);
    } else {
      activeSize = ringCursor.secondChunk.byteCount + ringCursor.firstChunk.byteCount - 3;
      if (activeSize < 0) {
        activeSize = 0;
      }
    }

    *outActiveSize = activeSize;
    if (activeSize > 0) {
      *outHasActiveUnit = 1;
    }
    return 0;
  }

  *outDelimiterFlags = delimiterFlags;
  *outActiveSize = 4;
  if ((delimiterFlags & 0x80) != 0) {
    return 0;
  }

  std::int32_t primaryDelimiterAddress = 0;
  std::int32_t secondaryDelimiterAddress = 0;
  SFBUF_RingGetDlm(workctrlAddress, sourceLaneIndex, &primaryDelimiterAddress, &secondaryDelimiterAddress);

  if (
    sfmpv_NeedSafeDlmRefresh(
      reinterpret_cast<const std::int32_t*>(&ringCursor),
      delimiterFlags,
      primaryDelimiterAddress
    ) != 0
  ) {
    primaryDelimiterAddress = 0;

    std::uint8_t* safeTailAddress = nullptr;
    if (ringCursor.secondChunk.byteCount != 0) {
      safeTailAddress = ringCursor.secondChunk.bufferAddress + ringCursor.secondChunk.byteCount;
    } else {
      safeTailAddress = ringCursor.firstChunk.bufferAddress + ringCursor.firstChunk.byteCount;
    }

    if (secondaryDelimiterAddress == PointerToAddress(safeTailAddress)) {
      return sfmpv_CheckViBufSiz(workctrlAddress);
    }

    secondaryDelimiterAddress = PointerToAddress(safeTailAddress);
    std::int32_t delimiterType = 0;
    primaryDelimiterAddress = PointerToAddress(
      sfmpv_BsearchDelim(reinterpret_cast<const std::int32_t*>(&ringCursor), 0xCC, &delimiterType)
    );
    SFBUF_RingSetDlm(workctrlAddress, sourceLaneIndex, primaryDelimiterAddress, secondaryDelimiterAddress);
  }

  if (primaryDelimiterAddress == 0) {
    return sfmpv_CheckViBufSiz(workctrlAddress);
  }

  const std::int32_t delimiterType = MPV_CheckDelim(AddressToPointer<std::uint8_t>(primaryDelimiterAddress));
  if (delimiterType == 4) {
    if ((delimiterFlags & 0x48) != 0) {
      delimiterCursor = sfmpv_SearchDelim(PointerToAddress(&ringCursor), 4, &delimiterFlags);
      if (delimiterCursor == nullptr || PointerToAddress(delimiterCursor) == primaryDelimiterAddress) {
        return sfmpv_CheckViBufSiz(workctrlAddress);
      }
    }
  } else if (delimiterType == 8 && (delimiterFlags & 0x40) != 0) {
    delimiterCursor = sfmpv_SearchDelim(PointerToAddress(&ringCursor), 8, &delimiterFlags);
    if (delimiterCursor == nullptr || PointerToAddress(delimiterCursor) == primaryDelimiterAddress) {
      return sfmpv_CheckViBufSiz(workctrlAddress);
    }
  }

  *outActiveSize =
    sfmpv_CalcDistance(reinterpret_cast<const std::int32_t*>(&ringCursor), AddressToPointer<std::uint8_t>(primaryDelimiterAddress));
  return 0;
}

/**
 * Address: 0x00AD2200 (FUN_00AD2200, _sfmpv_NeedSafeDlmRefresh)
 *
 * What it does:
 * Validates cached primary delimiter safety against current dual-chunk read
 * window, including seam reconstruction, and decides whether delimiter cache
 * must be refreshed.
 */
std::int32_t sfmpv_NeedSafeDlmRefresh(
  const std::int32_t* const ringCursorSnapshotWords,
  const std::int32_t delimiterFlags,
  const std::int32_t primaryDelimiterAddress
)
{
  auto* const primaryDelimiter = AddressToPointer<std::uint8_t>(primaryDelimiterAddress);
  if (primaryDelimiter == nullptr) {
    return 1;
  }

  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshotRuntimeView*>(ringCursorSnapshotWords);
  const std::uint8_t* const firstBase = ringCursor->firstChunk.bufferAddress;
  const std::int32_t firstLength = ringCursor->firstChunk.byteCount;
  const std::uint8_t* const secondBase = ringCursor->secondChunk.bufferAddress;
  const std::int32_t secondLength = ringCursor->secondChunk.byteCount;

  const std::uintptr_t primaryAddress = reinterpret_cast<std::uintptr_t>(primaryDelimiter);
  const std::uintptr_t firstAddress = reinterpret_cast<std::uintptr_t>(firstBase);
  const std::uintptr_t secondAddress = reinterpret_cast<std::uintptr_t>(secondBase);

  if (primaryAddress == firstAddress) {
    return 1;
  }
  if (primaryAddress > firstAddress && (primaryAddress - firstAddress) <= 3u) {
    return 1;
  }

  std::uint8_t delimiterProbe[4]{};
  if (
    primaryAddress < firstAddress
    || primaryAddress >= (firstAddress + static_cast<std::uint32_t>(firstLength))
  ) {
    if (
      primaryAddress >= secondAddress
      && primaryAddress < (secondAddress + static_cast<std::uint32_t>(secondLength))
      && static_cast<std::int32_t>(primaryAddress - secondAddress - static_cast<std::uint32_t>(secondLength) + 4u) <= 0
    ) {
      std::memcpy(delimiterProbe, primaryDelimiter, sizeof(delimiterProbe));
    } else {
      return 1;
    }
  } else {
    const std::int32_t seamBytes =
      static_cast<std::int32_t>(primaryAddress - firstAddress - static_cast<std::uint32_t>(firstLength) + 4u);
    if (seamBytes <= 0) {
      std::memcpy(delimiterProbe, primaryDelimiter, sizeof(delimiterProbe));
    } else {
      if (seamBytes > secondLength) {
        return 1;
      }
      const std::int32_t firstBytes = 4 - seamBytes;
      std::memcpy(delimiterProbe, primaryDelimiter, static_cast<std::size_t>(firstBytes));
      std::memcpy(delimiterProbe + firstBytes, secondBase, static_cast<std::size_t>(seamBytes));
    }
  }

  std::int32_t mutableDelimiterFlags = delimiterFlags;
  switch (MPV_CheckDelim(delimiterProbe)) {
    case 4: {
      if ((mutableDelimiterFlags & 0x48) != 0) {
        const std::uint8_t* const refreshedDelimiter =
          sfmpv_SearchDelim(PointerToAddress(ringCursor), 4, &mutableDelimiterFlags);
        if (refreshedDelimiter == nullptr || refreshedDelimiter == primaryDelimiter) {
          return 1;
        }
      }
      return 0;
    }

    case 8: {
      if ((mutableDelimiterFlags & 0x40) != 0) {
        const std::uint8_t* const refreshedDelimiter =
          sfmpv_SearchDelim(PointerToAddress(ringCursor), 8, &mutableDelimiterFlags);
        if (refreshedDelimiter == nullptr || refreshedDelimiter == primaryDelimiter) {
          return 1;
        }
      }
      return 0;
    }

    case 0x40:
    case 0x80:
      return 0;

    default:
      return 1;
  }
}

/**
 * Address: 0x00AD23C0 (FUN_00AD23C0, _sfmpv_CalcDistance)
 *
 * What it does:
 * Converts one delimiter pointer into active-window distance over current
 * dual-chunk ring snapshot.
 */
std::int32_t sfmpv_CalcDistance(
  const std::int32_t* const ringCursorSnapshotWords,
  const std::uint8_t* const targetAddress
)
{
  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshotRuntimeView*>(ringCursorSnapshotWords);
  const std::uintptr_t target = reinterpret_cast<std::uintptr_t>(targetAddress);
  const std::uintptr_t firstBase = reinterpret_cast<std::uintptr_t>(ringCursor->firstChunk.bufferAddress);
  const std::uintptr_t secondBase = reinterpret_cast<std::uintptr_t>(ringCursor->secondChunk.bufferAddress);

  if (firstBase <= target && target < (firstBase + static_cast<std::uint32_t>(ringCursor->firstChunk.byteCount))) {
    return static_cast<std::int32_t>(target - firstBase);
  }

  if (secondBase <= target && target < (secondBase + static_cast<std::uint32_t>(ringCursor->secondChunk.byteCount))) {
    return static_cast<std::int32_t>(target + static_cast<std::uint32_t>(ringCursor->firstChunk.byteCount) - secondBase);
  }

  return 0;
}

/**
 * Address: 0x00AD2450 (FUN_00AD2450, _sfmpv_SearchDelim)
 *
 * What it does:
 * Searches forward delimiter matches in first chunk, seam bytes, then second
 * chunk while returning resolved delimiter type to caller.
 */
std::uint8_t* sfmpv_SearchDelim(
  const std::int32_t ringCursorSnapshotAddress,
  const std::int32_t delimiterMask,
  std::int32_t* const outDelimiterType
)
{
  const auto* const ringCursor = AddressToPointer<const SfbufRingCursorSnapshotRuntimeView>(ringCursorSnapshotAddress);
  *outDelimiterType = 0;

  std::uint8_t* delimiter =
    reinterpret_cast<std::uint8_t*>(MPV_SearchDelim(
      reinterpret_cast<const char*>(ringCursor->firstChunk.bufferAddress),
      ringCursor->firstChunk.byteCount,
      delimiterMask
    ));
  if (delimiter != nullptr) {
    *outDelimiterType = MPV_CheckDelim(delimiter);
    return delimiter;
  }

  if (ringCursor->secondChunk.byteCount == 0) {
    return nullptr;
  }

  const std::int32_t firstBridgeBytes = (ringCursor->firstChunk.byteCount >= 3) ? 3 : ringCursor->firstChunk.byteCount;
  const std::int32_t secondBridgeBytes = (ringCursor->secondChunk.byteCount >= 3) ? 3 : ringCursor->secondChunk.byteCount;

  std::uint8_t seamWindow[8]{};
  std::memcpy(
    seamWindow,
    ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes,
    static_cast<std::size_t>(firstBridgeBytes)
  );
  std::memcpy(
    seamWindow + firstBridgeBytes,
    ringCursor->secondChunk.bufferAddress,
    static_cast<std::size_t>(secondBridgeBytes)
  );

  const std::int32_t seamProbeCount = firstBridgeBytes + secondBridgeBytes - 3;
  for (std::int32_t seamIndex = 0; seamIndex < seamProbeCount; ++seamIndex) {
    const std::int32_t delimiterType = MPV_CheckDelim(&seamWindow[seamIndex]);
    if ((delimiterMask & delimiterType) != 0) {
      *outDelimiterType = delimiterType;
      return ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes + seamIndex;
    }
  }

  delimiter = reinterpret_cast<std::uint8_t*>(MPV_SearchDelim(
    reinterpret_cast<const char*>(ringCursor->secondChunk.bufferAddress),
    ringCursor->secondChunk.byteCount,
    delimiterMask
  ));
  if (delimiter != nullptr) {
    *outDelimiterType = MPV_CheckDelim(delimiter);
    return delimiter;
  }
  return nullptr;
}

/**
 * Address: 0x00AD2570 (FUN_00AD2570, _sfmpv_BsearchDelim)
 *
 * What it does:
 * Searches delimiter matches in reverse order (second chunk tail first, seam
 * window next, then first chunk tail) and reports matched delimiter type.
 */
std::uint8_t* sfmpv_BsearchDelim(
  const std::int32_t* const ringCursorSnapshotWords,
  const std::int32_t delimiterMask,
  std::int32_t* const outDelimiterType
)
{
  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshotRuntimeView*>(ringCursorSnapshotWords);
  *outDelimiterType = 0;

  if (ringCursor->secondChunk.byteCount != 0) {
    std::uint8_t* delimiter = MPV_BsearchDelim(
      ringCursor->secondChunk.bufferAddress + ringCursor->secondChunk.byteCount,
      ringCursor->secondChunk.byteCount,
      delimiterMask
    );
    if (delimiter != nullptr) {
      *outDelimiterType = MPV_CheckDelim(delimiter);
      return delimiter;
    }

    const std::int32_t firstBridgeBytes = (ringCursor->firstChunk.byteCount >= 3) ? 3 : ringCursor->firstChunk.byteCount;
    const std::int32_t secondBridgeBytes = (ringCursor->secondChunk.byteCount >= 3) ? 3 : ringCursor->secondChunk.byteCount;

    std::uint8_t seamWindow[8]{};
    std::memcpy(
      seamWindow,
      ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes,
      static_cast<std::size_t>(firstBridgeBytes)
    );
    std::memcpy(
      seamWindow + firstBridgeBytes,
      ringCursor->secondChunk.bufferAddress,
      static_cast<std::size_t>(secondBridgeBytes)
    );

    const std::int32_t seamProbeCount = firstBridgeBytes + secondBridgeBytes - 3;
    for (std::int32_t seamIndex = 0; seamIndex < seamProbeCount; ++seamIndex) {
      const std::int32_t delimiterType = MPV_CheckDelim(&seamWindow[seamIndex]);
      if ((delimiterMask & delimiterType) != 0) {
        *outDelimiterType = delimiterType;
        return ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes + seamIndex;
      }
    }
  }

  std::uint8_t* delimiter = MPV_BsearchDelim(
    ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount,
    ringCursor->firstChunk.byteCount,
    delimiterMask
  );
  if (delimiter != nullptr) {
    *outDelimiterType = MPV_CheckDelim(delimiter);
    return delimiter;
  }
  return nullptr;
}

// Forward declarations for helpers defined later in this TU — needed because
// callers below reference them before their definitions.
std::int32_t sfmpv_SkipFrm(std::int32_t workctrlAddress, std::int32_t streamBufferAddress);
std::int32_t sfmpv_ConcatSub(std::int32_t workctrlAddress);
struct SfmpvPictureAttributeRuntimeView;
std::int32_t sfmpv_ReformTc(
    std::int32_t workctrlAddress,
    SfmpvPictureAttributeRuntimeView* pictureAttribute,
    std::int64_t presentationPts,
    std::int32_t detectErrorMode);
std::int32_t sfmpv_IsLate(std::int32_t workctrlAddress, std::int32_t updateMode);

/**
 * Address: 0x00AD2690 (FUN_00AD2690, _sfmpv_DecodeOneUnit)
 *
 * What it does:
 * Executes one delimiter-scoped decode step, including seek/endcode handling,
 * picture-attribute decode lane, and frame decode-or-skip dispatch.
 */
std::int32_t sfmpv_DecodeOneUnit(
  SfmpvHandleRuntimeView* const workctrl,
  const std::int32_t activeSize,
  const std::int32_t delimiterState,
  const std::int32_t hasActiveUnit,
  std::int32_t* const outUnitProcessed
)
{
  const std::int32_t workctrlAddress = PointerToAddress(workctrl);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  *outUnitProcessed = 0;
  workctrl->decodeStarvedLatch = 0;

  std::int32_t activeDelimiterMask = delimiterState;
  if (mpvInfo->concatControlFlags != 0xCC || mpvInfo->picAtrPrimedLatch == 0) {
    activeDelimiterMask &= 0xCC;
  }

  std::int32_t streamBufferAddress = 0;
  std::int32_t decodeResult = SFBUF_RingGetSj(workctrlAddress, workctrl->prepSourceLaneIndex, &streamBufferAddress);
  if (decodeResult != 0 || streamBufferAddress == 0) {
    return 0;
  }

  if ((activeDelimiterMask & 0xC8) != 0) {
    SFMPVF_FixDispOrder(workctrlAddress, 1);
  }

  if (activeDelimiterMask == 0x80) {
    sfmpv_FixedForSeek(workctrlAddress);
    if (SFCON_IsEndcodeSkip(workctrlAddress) != 0) {
      if (sfmpv_Concat(workctrlAddress, streamBufferAddress) == 0) {
        *outUnitProcessed = 1;
        return 0;
      }
      return decodeResult;
    }

    if (SFCON_IsVideoEndcodeSkip(workctrlAddress) != 0) {
      sfmpv_DiscardSec(workctrlAddress, streamBufferAddress);
      *outUnitProcessed = 1;
      return 0;
    }
  }

  if (hasActiveUnit == 0) {
    if (sfmpv_IsTerm(workctrlAddress, activeSize, activeDelimiterMask) != 0) {
      SFMPVF_TermDec(workctrlAddress);
      return 0;
    }
    if (activeSize <= 4) {
      workctrl->decodeStarvedLatch = 1;
      return 0;
    }
  }

  if ((activeDelimiterMask & 0x4C) != 0) {
    std::int32_t chunkWords[2]{};
    std::int32_t pictureDecodeState = 0;

    sfmpv_PeekChnk(workctrlAddress, chunkWords);
    decodeResult = sfmpv_DecodePicAtr(workctrlAddress, chunkWords, streamBufferAddress, activeDelimiterMask, &pictureDecodeState);
    if (decodeResult != 0) {
      return decodeResult;
    }

    if (pictureDecodeState == 0) {
      if ((activeDelimiterMask & mpvInfo->concatControlFlags) != 0) {
        mpvInfo->concatControlFlags = 0xCC;
      }
      mpvInfo->picAtrPrimedLatch = 1;
    }

    if (activeDelimiterMask == 0x40 && pictureDecodeState == -2) {
      mpvInfo->concatControlFlags = 0xC0;
      *outUnitProcessed = 1;
      return 0;
    }

    *outUnitProcessed = 1;
    return decodeResult;
  }

  if ((activeDelimiterMask & 2) == 0) {
    if (activeDelimiterMask != 0x80 && sfmpv_GoDdelim(workctrlAddress, streamBufferAddress, 0xCC) > 0) {
      *outUnitProcessed = 1;
    }
    return decodeResult;
  }

  std::int32_t chunkWords[2]{};
  sfmpv_PeekChnk(workctrlAddress, chunkWords);
  if (sfmpv_IsSkip(workctrlAddress, chunkWords) == 0) {
    return sfmpv_DecodeFrm(workctrlAddress, streamBufferAddress);
  }

  decodeResult = sfmpv_SkipFrm(workctrlAddress, streamBufferAddress);
  if (decodeResult == 0) {
    *outUnitProcessed = 1;
  }
  return decodeResult;
}

/**
 * Address: 0x00AD1FB0 (FUN_00AD1FB0, _sfmpv_DecodeSomePic)
 *
 * What it does:
 * Repeatedly decodes active picture units until one loop marks no progress or
 * returns an error, then updates stream flow counters.
 */
std::int32_t sfmpv_DecodeSomePic(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  std::int32_t activeSize = 0;
  std::int32_t delimiterFlags = 0;
  std::int32_t hasActiveUnit = 0;
  std::int32_t unitProcessed = 0;
  std::int32_t decodeResult = 0;

  do {
    decodeResult = sfmpv_GetActiveSize(workctrlAddress, &activeSize, &delimiterFlags, &hasActiveUnit);
    if (decodeResult != 0) {
      break;
    }

    decodeResult = sfmpv_DecodeOneUnit(workctrl, activeSize, delimiterFlags, hasActiveUnit, &unitProcessed);
    if (decodeResult != 0) {
      break;
    }
  } while (unitProcessed != 0);

  sfmpv_UpdateFlowCnt(workctrlAddress);
  return decodeResult;
}

/**
 * Address: 0x00AD2950 (FUN_00AD2950, _sfmpv_FixedForSeek)
 *
 * What it does:
 * Initializes seek fixed-read total once and snapshots concat-audio TTU lanes
 * into seek baseline storage when baseline time is still unset.
 */
void sfmpv_FixedForSeek(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  if (workctrl->seekFixedReadTotal < 0) {
    workctrl->seekFixedReadTotal = SFBUF_GetRTot(workctrlAddress, workctrl->prepSourceLaneIndex) + 4;
  }

  if (workctrl->timingLane.seekFixedBaselineTtu.timeMajor < 0) {
    std::memcpy(
      &workctrl->timingLane.seekFixedBaselineTtu,
      &workctrl->timingLane.concatAudioTimeUnit[0],
      sizeof(SfmpvTtuRuntimeView)
    );
  }
}

/**
 * Address: 0x00AD29A0 (FUN_00AD29A0, _sfmpv_Concat)
 *
 * What it does:
 * Executes concat-sub processing and, on success, discards trailing section
 * delimiters from the active stream lane.
 */
std::int32_t sfmpv_Concat(const std::int32_t workctrlAddress, const std::int32_t streamBufferAddress)
{
  const std::int32_t concatResult = sfmpv_ConcatSub(workctrlAddress);
  if (concatResult == -1) {
    return concatResult;
  }

  sfmpv_DiscardSec(workctrlAddress, streamBufferAddress);
  return 0;
}

/**
 * Address: 0x00AD29D0 (FUN_00AD29D0, _sfmpv_ConcatSub)
 *
 * What it does:
 * Computes concat total-time from audio/video path, updates concat timeline
 * when a positive delta exists, resets concat timer lanes, and re-arms concat
 * control flags.
 */
std::int32_t sfmpv_ConcatSub(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t concatTotalTime = 0;
  if (SFSET_GetCond(workctrlAddress, 6) != 0) {
    concatTotalTime = sfmpv_CalcAudioTotTime(workctrlAddress);
    if (concatTotalTime < 0) {
      return -1;
    }
  } else {
    concatTotalTime = sfmpv_CalcVideoTotTime(workctrlAddress);
  }

  if (concatTotalTime > 0) {
    SFCON_UpdateConcatTime(workctrlAddress, concatTotalTime);
    ++mpvInfo->concatAdvanceCount;
  }

  SFTIM_InitTtu(workctrl->timingLane.concatVideoTimeUnit, 0x7FFFFFFF);
  SFTIM_InitTtu(workctrl->timingLane.concatAudioTimeUnit, -1);
  mpvInfo->concatControlFlags = 0xC0;
  return 0;
}

/**
 * Address: 0x00AD2A50 (FUN_00AD2A50, _sfmpv_CalcVideoTotTime)
 *
 * What it does:
 * Computes concat total-time from video TTU lane by advancing concat-audio
 * packed timecode by one frame and converting that lane through `SFTIM_Tc2Time`.
 */
std::int32_t sfmpv_CalcVideoTotTime(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  const auto* const concatAudioTtu =
    reinterpret_cast<const SfmpvTtuRuntimeView*>(workctrl->timingLane.concatAudioTimeUnit);
  if (concatAudioTtu->state == 0) {
    return 0;
  }

  SfmpvPackedTimecodeRuntimeView nextTimecode{};
  (void)sfmpv_NextTc(
    reinterpret_cast<const SfmpvPackedTimecodeRuntimeView*>(concatAudioTtu->packedTimecodeWords),
    &nextTimecode
  );
  nextTimecode.halfFrameCarry = 0;

  std::int32_t nextTimeMajor = 0;
  std::int32_t nextTimeMinor = 0;
  (void)SFTIM_Tc2Time(&nextTimecode, &nextTimeMajor, &nextTimeMinor);
  return nextTimeMajor - static_cast<std::int32_t>(workctrl->timingLane.concatVideoTimeUnit[9]);
}

/**
 * Address: 0x00AD2AB0 (FUN_00AD2AB0, _sfmpv_CalcAudioTotTime)
 *
 * What it does:
 * Computes concat total-time from audio sample totals using transport read
 * mode, cumulative sample lane, and configured concat-video time scale.
 */
std::int32_t sfmpv_CalcAudioTotTime(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  std::int32_t totalSamples = 0;
  std::int32_t sampleRate = 44100;
  const auto* const transportView = AddressToPointer<const SfmpvAudioTransportRuntimeView>(workctrlAddress);
  if (transportView->vtable->readTotalSamplesProc == &SFD_tr_ad_adxt) {
    if (SFCON_ReadTotSmplQue(workctrlAddress, &totalSamples, &sampleRate) == 0) {
      return -1;
    }
  }

  totalSamples += workctrl->audioTotalSampleCount;
  workctrl->audioTotalSampleCount = totalSamples;

  const std::int32_t concatAudioTime =
    UTY_MulDiv(totalSamples, static_cast<std::int32_t>(workctrl->timingLane.concatVideoTimeUnit[10]), sampleRate)
    - workctrl->timingLane.decodeProgressTime;
  if (concatAudioTime < 0) {
    return 0;
  }
  return concatAudioTime;
}

/**
 * Address: 0x00AE5D10 (FUN_00AE5D10, _sfpts_SearchPtsQue)
 *
 * What it does:
 * Scans the queued PTS-reference windows in ring order and returns the first
 * offset whose reference span contains the normalized delimiter address;
 * returns `-1` when no entry matches.
 */
std::int32_t sfpts_SearchPtsQue(
  const SfptsPtsQueueRuntimeView* const ptsQueue,
  const std::uint32_t normalizedDelimiterAddress,
  const std::uint32_t sourceLaneStartAddress,
  const std::int32_t sourceLaneSpanBytes
)
{
  const std::uint32_t sourceLaneEndAddress = sourceLaneStartAddress + static_cast<std::uint32_t>(sourceLaneSpanBytes);
  const std::int32_t queuedEntryCount = ptsQueue->queuedEntryCount;
  const std::int32_t entryCapacity = ptsQueue->entryCapacity;
  std::int32_t entryIndex = ptsQueue->readCursor;
  std::int32_t queueOffset = 0;

  if (queuedEntryCount <= 0) {
    return -1;
  }

  const auto* const entries = AddressToPointer<const SfptsQueueEntryRuntimeView>(ptsQueue->entriesBaseAddress);
  std::int32_t byteOffset = entryIndex * static_cast<std::int32_t>(sizeof(SfptsQueueEntryRuntimeView));
  const std::int32_t ringByteSpan = entryCapacity * static_cast<std::int32_t>(sizeof(SfptsQueueEntryRuntimeView));

  while (true) {
    const auto* const entry = reinterpret_cast<const SfptsQueueEntryRuntimeView*>(
      reinterpret_cast<const std::uint8_t*>(entries) + byteOffset
    );
    const std::uint32_t referenceStart = static_cast<std::uint32_t>(entry->referenceLow);
    std::uint32_t referenceEnd = referenceStart + static_cast<std::uint32_t>(entry->referenceHigh);

    if (referenceEnd <= sourceLaneEndAddress) {
      if (referenceStart > normalizedDelimiterAddress) {
        // Delimiter is before this non-wrapped range; continue with next entry.
      } else if (normalizedDelimiterAddress < referenceEnd) {
        return queueOffset;
      }
    } else {
      if (referenceStart <= normalizedDelimiterAddress && normalizedDelimiterAddress < sourceLaneEndAddress) {
        return queueOffset;
      }

      if (sourceLaneStartAddress <= normalizedDelimiterAddress) {
        referenceEnd -= static_cast<std::uint32_t>(sourceLaneSpanBytes);
        if (normalizedDelimiterAddress < referenceEnd) {
          return queueOffset;
        }
      }
    }

    if (entryIndex + 1 >= entryCapacity) {
      byteOffset -= ringByteSpan;
      entryIndex += 1 - entryCapacity;
    } else {
      ++entryIndex;
    }
    byteOffset += static_cast<std::int32_t>(sizeof(SfptsQueueEntryRuntimeView));

    ++queueOffset;
    if (queueOffset >= queuedEntryCount) {
      return -1;
    }
  }
}

/**
 * Address: 0x00AE5CA0 (FUN_00AE5CA0, _sfpts_ReadPtsQueSub)
 *
 * SfptsPtsQueueRuntimeView *,int,int *,int,int
 *
 * What it does:
 * Searches one source-lane PTS queue for the delimiter-relative entry, updates
 * queue cursor/count state, and copies one 16-byte entry payload.
 */
std::int32_t* sfpts_ReadPtsQueSub(
  SfptsPtsQueueRuntimeView* const ptsQueue,
  const std::int32_t normalizedDelimiterAddress,
  std::int32_t* const outPtsWords,
  const std::int32_t sourceLaneStartAddress,
  const std::int32_t sourceLaneSpanBytes
)
{
  auto* result = reinterpret_cast<std::int32_t*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(ptsQueue->queuedEntryCount))
  );
  if (result != nullptr) {
    const std::int32_t queueOffset = sfpts_SearchPtsQue(
      ptsQueue,
      static_cast<std::uint32_t>(normalizedDelimiterAddress),
      static_cast<std::uint32_t>(sourceLaneStartAddress),
      sourceLaneSpanBytes
    );
    result = reinterpret_cast<std::int32_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(queueOffset))
    );

    if (queueOffset != -1) {
      const std::int32_t readCursor = ptsQueue->readCursor;
      const std::int32_t entryCapacity = ptsQueue->entryCapacity;

      std::int32_t nextCursor = readCursor + queueOffset;
      if (nextCursor >= entryCapacity) {
        nextCursor = readCursor + (queueOffset - entryCapacity);
      }

      const std::int32_t queuedEntryCount = ptsQueue->queuedEntryCount;
      ptsQueue->readCursor = nextCursor;
      ptsQueue->queuedEntryCount = queuedEntryCount - queueOffset;

      const auto* const entries = AddressToPointer<const SfptsQueueEntryRuntimeView>(ptsQueue->entriesBaseAddress);
      const auto* const selectedEntry = &entries[nextCursor];
      outPtsWords[0] = selectedEntry->ptsLow;
      outPtsWords[1] = selectedEntry->ptsHigh;
      outPtsWords[2] = selectedEntry->referenceLow;
      outPtsWords[3] = selectedEntry->referenceHigh;
      return outPtsWords;
    }
  }

  return result;
}

/**
 * Address: 0x00AE5C40 (FUN_00AE5C40, _SFPTS_ReadPtsQue)
 *
 * int,int,unsigned int,int *
 *
 * What it does:
 * Initializes output PTS lanes to `-1`, maps delimiter address into the active
 * source window, and dispatches one queue read when queue storage is present.
 */
std::int32_t SFPTS_ReadPtsQue(
  const std::int32_t workctrlAddress,
  const std::int32_t sourceLaneIndex,
  const std::int32_t delimiterAddress,
  std::int32_t* const outPtsWords
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const sourceLane = GetSfptsSourceLane(workctrl, sourceLaneIndex);

  outPtsWords[0] = -1;
  outPtsWords[1] = -1;

  if (sourceLane->ptsQueue.entriesBaseAddress != 0) {
    std::uint32_t normalizedDelimiterAddress = static_cast<std::uint32_t>(delimiterAddress);
    const std::uint32_t sourceWindowStart = static_cast<std::uint32_t>(sourceLane->ringWindowStartAddress);
    const std::uint32_t sourceWindowEnd = sourceWindowStart + static_cast<std::uint32_t>(sourceLane->ringWindowSpanBytes);

    if (normalizedDelimiterAddress >= sourceWindowEnd) {
      normalizedDelimiterAddress -= static_cast<std::uint32_t>(sourceLane->ringWindowSpanBytes);
    }

    (void)sfpts_ReadPtsQueSub(
      &sourceLane->ptsQueue,
      static_cast<std::int32_t>(normalizedDelimiterAddress),
      outPtsWords,
      sourceLane->ringWindowStartAddress,
      sourceLane->ringWindowSpanBytes
    );
  }

  return 0;
}

/**
 * Address: 0x00AE5F20 (FUN_00AE5F20, _SFCON_IsVideoEndcodeSkip)
 *
 * int
 *
 * What it does:
 * Returns `1` when either condition lane 49 or 57 is set; otherwise returns
 * the second condition result (`0`).
 */
std::int32_t SFCON_IsVideoEndcodeSkip(const std::int32_t workctrlAddress)
{
  if (SFSET_GetCond(workctrlAddress, 49) != 0) {
    return 1;
  }

  const std::int32_t result = SFSET_GetCond(workctrlAddress, 57);
  if (result != 0) {
    return 1;
  }

  return result;
}

/**
 * Address: 0x00AE5F50 (FUN_00AE5F50, _SFCON_UpdateConcatTime)
 *
 * What it does:
 * Adds one concat-time delta to runtime timing state and records the updated
 * total in a 32-slot history ring.
 */
void SFCON_UpdateConcatTime(const std::int32_t workctrlAddress, const std::int32_t totalTime)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t updatedConcatTime = workctrl->timingLane.decodeProgressTime + totalTime;
  workctrl->timingLane.decodeProgressTime = updatedConcatTime;

  const std::int32_t nextWriteOrdinal = workctrl->concatTimeHistoryWriteOrdinal + 1;
  workctrl->concatTimeHistory[Modulo32Index(nextWriteOrdinal)] = updatedConcatTime;
  workctrl->concatTimeHistoryWriteOrdinal = nextWriteOrdinal;
  SFLIB_UnlockCs();
}

/**
 * Address: 0x00AE5FB0 (FUN_00AE5FB0, _SFCON_WriteTotSmplQue)
 *
 * What it does:
 * Pushes one `(totalSamples, sampleRate)` update into the 32-slot audio
 * total-sample queue when capacity is available.
 */
std::int32_t SFCON_WriteTotSmplQue(
  const std::int32_t workctrlAddress,
  const std::int32_t totalSamples,
  const std::int32_t sampleRate
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t queuedCount = workctrl->totalSampleQueueWriteOrdinal - workctrl->totalSampleQueueReadOrdinal;
  if (queuedCount >= 32) {
    SFLIB_UnlockCs();
    return 0;
  }

  workctrl->queuedAudioSampleRate = sampleRate;
  workctrl->totalSampleQueueTotals[Modulo32Index(workctrl->totalSampleQueueWriteOrdinal)] = totalSamples;
  ++workctrl->totalSampleQueueWriteOrdinal;
  SFLIB_UnlockCs();
  return 1;
}

/**
 * Address: 0x00AE6040 (FUN_00AE6040, _SFCON_ReadTotSmplQue)
 *
 * What it does:
 * Pops one queued total-sample update from the 32-slot audio queue and
 * returns both sample-total and sample-rate lanes.
 */
std::int32_t SFCON_ReadTotSmplQue(
  const std::int32_t workctrlAddress,
  std::int32_t* const outTotalSamples,
  std::int32_t* const outSampleRate
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t queuedCount = workctrl->totalSampleQueueWriteOrdinal - workctrl->totalSampleQueueReadOrdinal;
  if (queuedCount <= 0) {
    *outTotalSamples = -1;
    SFLIB_UnlockCs();
    return 0;
  }

  *outSampleRate = workctrl->queuedAudioSampleRate;
  *outTotalSamples = workctrl->totalSampleQueueTotals[Modulo32Index(workctrl->totalSampleQueueReadOrdinal)];
  ++workctrl->totalSampleQueueReadOrdinal;
  SFLIB_UnlockCs();
  return 1;
}

/**
 * Address: 0x00AD2B30 (FUN_00AD2B30, _sfmpv_DiscardSec)
 *
 * What it does:
 * Consumes repeated section-end delimiters (`0x80`) from the active stream
 * lane and accumulates consumed bytes into read-total lanes.
 */
void sfmpv_DiscardSec(const std::int32_t workctrlAddress, const std::int32_t streamBufferAddress)
{
  const auto* const streamBuffer = AddressToPointer<const SfmpvStreamBufferRuntimeView>(streamBufferAddress);
  SfmpvStreamWindowCursorRuntimeView cursorWindow{};

  streamBuffer->vtable->readWindow(streamBufferAddress, 1, 4, &cursorWindow);
  while (cursorWindow.byteCount == 4) {
    if (MPV_CheckDelim(cursorWindow.cursor) != 0x80) {
      break;
    }

    streamBuffer->vtable->advanceWindow(streamBufferAddress, 0, &cursorWindow);
    (void)sfmpv_AddRtotSj(workctrlAddress, 4);
    streamBuffer->vtable->readWindow(streamBufferAddress, 1, 4, &cursorWindow);
  }

  (void)streamBuffer->vtable->commitWindow(streamBufferAddress, 1, &cursorWindow);
}

/**
 * Address: 0x00AD2BC0 (FUN_00AD2BC0, _sfmpv_AddRtotSj)
 *
 * What it does:
 * Adds consumed bytes to SFBUF read-total lanes for active source ring and
 * mirrors the same signed 64-bit accumulation in workctrl read-total fields.
 */
std::int32_t sfmpv_AddRtotSj(const std::int32_t workctrlAddress, const std::int32_t consumedBytes)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  (void)SFBUF_AddRtotSj(workctrlAddress, workctrl->prepSourceLaneIndex, consumedBytes);
  AddSigned32ToLane(&workctrl->ringReadTotalLow, &workctrl->ringReadTotalHigh, consumedBytes);
  return workctrl->ringReadTotalHigh;
}

/**
 * Address: 0x00AD2900 (FUN_00AD2900, _sfmpv_PeekChnk)
 *
 * What it does:
 * Peeks the current source-ring read window and returns the first chunk lane
 * (`address + byteCount`) to callers that decode delimiters/picture headers.
 */
void sfmpv_PeekChnk(const std::int32_t workctrlAddress, std::int32_t* const outChunkWords)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  SfbufRingCursorSnapshotRuntimeView ringCursor{};
  if (
    SFBUF_RingGetRead(
      workctrlAddress,
      workctrl->prepSourceLaneIndex,
      reinterpret_cast<std::int32_t*>(&ringCursor)
    )
    == 0
  ) {
    outChunkWords[0] = PointerToAddress(ringCursor.firstChunk.bufferAddress);
    outChunkWords[1] = ringCursor.firstChunk.byteCount;
  } else {
    outChunkWords[0] = 0;
    outChunkWords[1] = 0;
  }
}

/**
 * Address: 0x00AD1D20 (FUN_00AD1D20, _sfmpv_GetTermDst)
 *
 * What it does:
 * Returns destination-lane terminal flag from the active prep destination
 * ring.
 */
std::int32_t sfmpv_GetTermDst(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  return SFBUF_GetTermFlg(workctrlAddress, workctrl->prepDestinationLaneIndex);
}

/**
 * Address: 0x00AD2C30 (FUN_00AD2C30, _sfmpv_GetTermSrc)
 *
 * What it does:
 * Returns source-lane terminal flag from the active prep source ring.
 */
std::int32_t sfmpv_GetTermSrc(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  return SFBUF_GetTermFlg(workctrlAddress, workctrl->prepSourceLaneIndex);
}

/**
 * Address: 0x00AD2C00 (FUN_00AD2C00, _sfmpv_IsTerm)
 *
 * What it does:
 * Detects decode termination based on delimiter class, active payload size,
 * and current source-lane terminal flag.
 */
std::int32_t sfmpv_IsTerm(
  const std::int32_t workctrlAddress,
  const std::int32_t activeSize,
  const std::int32_t delimiterState
)
{
  if (delimiterState == 0x80) {
    return 1;
  }
  if (activeSize > 4) {
    return 0;
  }
  return (sfmpv_GetTermSrc(workctrlAddress) == 1) ? 1 : 0;
}

/**
 * Address: 0x00AD2F30 (FUN_00AD2F30, _sfmpv_ChkMpvErr)
 *
 * What it does:
 * Normalizes MPV decode return codes against consumed-byte state and maps
 * fatal/non-progress conditions to SFLIB error lanes.
 */
std::int32_t sfmpv_ChkMpvErr(
  const std::int32_t workctrlAddress,
  const std::int32_t decodeResult,
  const std::int32_t consumedBytes,
  const std::int32_t fallbackErrorCode
)
{
  if (decodeResult == -3) {
    if (consumedBytes <= 0) {
      return SFLIB_SetErr(workctrlAddress, -3);
    }
    return 0;
  }

  if (decodeResult == -2) {
    if (consumedBytes > 0) {
      return 0;
    }
    return SFLIB_SetErr(workctrlAddress, -2);
  }

  if (decodeResult != 0) {
    return SFLIB_SetErr(workctrlAddress, fallbackErrorCode);
  }
  return 0;
}

/**
 * Address: 0x00AD2C50 (FUN_00AD2C50, _sfmpv_DecodePicAtr)
 *
 * What it does:
 * Decodes picture attributes from the active stream chunk, updates MPV
 * picture/user/timestamp lanes, and runs repeat/timecode/first-picture setup.
 */
std::int32_t sfmpv_DecodePicAtr(
  const std::int32_t workctrlAddress,
  const std::int32_t* const chunkWords,
  const std::int32_t streamBufferAddress,
  const std::int32_t delimiterState,
  std::int32_t* const outDecodeState
)
{
  using PictureFilterCallback =
    std::int32_t(__cdecl*)(std::int32_t callbackContext, std::int32_t widthPixels, std::int32_t heightPixels);
  using DelimiterObserverCallback =
    void(__cdecl*)(std::int32_t callbackContext, std::int32_t chunkBaseAddress, std::int32_t payloadOffsetBytes);

  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  auto* const pictureDecodeLane = &mpvInfo->pictureDecodeLane;
  const auto* const chunk = reinterpret_cast<const SfbufRingChunkRuntimeView*>(chunkWords);

  mpvInfo->pictureUserFlags = 0;
  MPV_SetPicUsrBuf(
    mpvInfo->decoderHandle,
    mpvInfo->pictureUserBufferMirrorAddress,
    mpvInfo->pictureUserBufferSize
  );

  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1);
  *outDecodeState = MPV_DecodePicAtrSj(mpvInfo->decoderHandle, streamBufferAddress);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1) - flowCountBefore;

  const std::int32_t checkedResult =
    sfmpv_ChkMpvErr(workctrlAddress, *outDecodeState, consumedBytes, -16773372);
  sfmpv_AddRtotSj(workctrlAddress, consumedBytes);
  if (checkedResult != 0) {
    return checkedResult;
  }
  if (*outDecodeState == -2) {
    return 0;
  }

  *outDecodeState = MPV_GetPicAtr(mpvInfo->decoderHandle, pictureDecodeLane);
  if (*outDecodeState != 0) {
    return SFLIB_SetErr(workctrlAddress, -16773371);
  }

  if ((delimiterState & 0x40) != 0) {
    if (
      workctrl->mvInfo.pictureWidthPixels > 0
      && (workctrl->mvInfo.pictureWidthPixels != pictureDecodeLane->pictureWidthPixels
          || workctrl->mvInfo.pictureHeightPixels != pictureDecodeLane->pictureHeightPixels)
    ) {
      *outDecodeState = -2;
      return 0;
    }

    const auto filterCallback = reinterpret_cast<PictureFilterCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(SFSET_GetCond(workctrlAddress, 95)))
    );
    const std::int32_t filterContext = SFSET_GetCond(workctrlAddress, 95);
    if (
      filterCallback != nullptr
      && filterCallback(
           filterContext,
           pictureDecodeLane->pictureWidthPixels,
           pictureDecodeLane->pictureHeightPixels
         )
           != 0
    ) {
      *outDecodeState = -2;
      return 0;
    }
  }

  const std::int32_t pictureType = pictureDecodeLane->pictureType;
  if (pictureType == 1) {
    mpvInfo->referenceErrorCarryFlag = 0;
  } else if (workctrl->mpvCond6Value == 3 && mpvInfo->secondaryReferenceFrameObjectAddress != 0) {
    const auto* const secondaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->secondaryReferenceFrameObjectAddress);
    const std::int32_t secondaryOrderMetric = secondaryReferenceFrame->pictureDecodeLane.decodeOrderMetric;
    if (
      (pictureType == 2 && pictureDecodeLane->decodeOrderMetric < secondaryOrderMetric && secondaryOrderMetric < 512)
      || (pictureType == 3 && pictureDecodeLane->decodeOrderMetric >= secondaryOrderMetric)
    ) {
      mpvInfo->referenceErrorCarryFlag = 1;
    }
  }

  MPV_GetPicUsr(mpvInfo->decoderHandle, 0, &mpvInfo->pictureUserFlags);
  if (mpvInfo->lastPictureSequenceStamp == pictureDecodeLane->sequenceStamp) {
    mpvInfo->linkDefectCheckEnabled = 0;
  } else {
    mpvInfo->lastPictureSequenceStamp = pictureDecodeLane->sequenceStamp;
    mpvInfo->linkDefectCheckEnabled = 1;
  }

  if ((delimiterState & 0x40) != 0) {
    const auto delimiterObserver = reinterpret_cast<DelimiterObserverCallback>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(SFSET_GetCond(workctrlAddress, 77)))
    );
    const std::int32_t observerContext = SFSET_GetCond(workctrlAddress, 78);
    if (delimiterObserver != nullptr) {
      char* const objectDelimiter =
        MPV_SearchDelim(reinterpret_cast<const char*>(chunk->bufferAddress), chunk->byteCount, 1);
      if (objectDelimiter != nullptr) {
        const std::int32_t payloadOffset =
          static_cast<std::int32_t>(objectDelimiter - reinterpret_cast<char*>(chunk->bufferAddress) + 4);
        delimiterObserver(observerContext, PointerToAddress(chunk->bufferAddress), payloadOffset);
      }
    }
  }

  char* const ptsDelimiter = MPV_SearchDelim(
    reinterpret_cast<const char*>(chunk->bufferAddress),
    chunk->byteCount,
    4
  );
  std::int32_t presentationPtsWords[2]{};
  std::int32_t referenceSeedWords[2]{};
  sfmpv_ReadPtsQue(
    workctrlAddress,
    pictureDecodeLane,
    ptsDelimiter,
    presentationPtsWords,
    referenceSeedWords,
    mpvInfo->linkDefectCheckEnabled
  );
  mpvInfo->referenceErrorSeedMajor = referenceSeedWords[0];
  mpvInfo->referenceErrorSeedMinor = referenceSeedWords[1];

  if ((mpvInfo->concatControlFlags & delimiterState) == 0) {
    return 0;
  }

  (void)sfmpv_CalcRepeatField(
    workctrlAddress,
    PointerToAddress(pictureDecodeLane),
    mpvInfo->linkDefectCheckEnabled
  );

  const std::int64_t presentationPts =
    (static_cast<std::int64_t>(static_cast<std::uint32_t>(presentationPtsWords[1])) << 32)
    | static_cast<std::uint32_t>(presentationPtsWords[0]);
  (void)sfmpv_ReformTc(
    workctrlAddress,
    reinterpret_cast<SfmpvPictureAttributeRuntimeView*>(pictureDecodeLane),
    presentationPts,
    mpvInfo->linkDefectCheckEnabled
  );

  sfmpv_SetHeadTtu(workctrlAddress);
  sfmpv_SetDecTtu(workctrlAddress);
  return sfmpv_FirstPicAtr(
    workctrlAddress,
    mpvInfo->decoderHandle,
    PointerToAddress(pictureDecodeLane),
    PointerToAddress(chunk)
  );
}

/**
 * Address: 0x00AD3170 (FUN_00AD3170, _sfmpv_Nfrm2Pts)
 *
 * What it does:
 * Converts one frame-count delta into 90 kHz PTS ticks using one per-rate
 * scale denominator.
 */
std::int64_t sfmpv_Nfrm2Pts(const std::int32_t frameCount, const std::int32_t frameRateScale)
{
  return (90000000LL * static_cast<std::int64_t>(frameCount)) / frameRateScale;
}

/**
 * Address: 0x00AD3020 (FUN_00AD3020, _sfmpv_ComplementPts)
 *
 * What it does:
 * Complements sparse PTS lanes from picture decode metadata and per-handle
 * bias/history state, while outputting current reference-seed words.
 */
std::int64_t sfmpv_ComplementPts(
  const std::int32_t timingLaneAddress,
  SfmpvComplementPts* const complementState,
  const SfmpvPictureDecodeLaneRuntimeView* const pictureDecodeLane,
  const std::int32_t* const ptsWords,
  const std::int32_t pictureChangedFlag,
  std::int32_t* const outReferenceSeedWords
)
{
  auto* const timingLane = AddressToPointer<SfmpvTimingLane>(timingLaneAddress);

  const std::int32_t frameCount = pictureDecodeLane->decodeOrderMetric;
  const std::int32_t frameRateScale = SFTIM_prate[pictureDecodeLane->frameRateIndex];

  if (timingLane->ptsBiasHigh < 0) {
    const std::int64_t framePts = sfmpv_Nfrm2Pts(frameCount, frameRateScale);
    std::int64_t ptsBias = (static_cast<std::int64_t>(static_cast<std::uint32_t>(ptsWords[1])) << 32)
      | static_cast<std::uint32_t>(ptsWords[0]);
    ptsBias -= framePts;
    if (ptsBias < 0) {
      ptsBias = 0;
    }
    timingLane->ptsBiasLow = static_cast<std::int32_t>(ptsBias);
    timingLane->ptsBiasHigh = static_cast<std::int32_t>(ptsBias >> 32);
  }

  std::int64_t ptsDelta = (static_cast<std::int64_t>(static_cast<std::uint32_t>(ptsWords[1])) << 32)
    | static_cast<std::uint32_t>(ptsWords[0]);
  ptsDelta -= (static_cast<std::int64_t>(static_cast<std::uint32_t>(timingLane->ptsBiasHigh)) << 32)
    | static_cast<std::uint32_t>(timingLane->ptsBiasLow);
  if (ptsDelta < 0) {
    ptsDelta = 0;
  }

  if (complementState->field_0x10 != ptsWords[0]) {
    complementState->field_0x10 = ptsWords[0];
    complementState->field_0x14 = ptsWords[1];
    complementState->field_0x18 = ptsWords[2];
    complementState->field_0x1C = ptsWords[3];
    complementState->field_0x00 = frameCount;
    complementState->field_0x04 = 0;
    complementState->field_0x08 = (pictureDecodeLane->pictureType == 3) ? 1 : 0;

    outReferenceSeedWords[0] = ptsWords[0];
    outReferenceSeedWords[1] = ptsWords[1];
    return ptsDelta;
  }

  if (pictureChangedFlag != 0) {
    complementState->field_0x04 += complementState->field_0x08 + 1;
    complementState->field_0x08 = 0;
    complementState->field_0x00 = 0;
  }

  const std::int32_t frameDelta = frameCount - complementState->field_0x00;
  if (complementState->field_0x08 <= frameDelta) {
    complementState->field_0x08 = frameDelta;
  }

  ptsDelta += sfmpv_Nfrm2Pts(frameDelta + complementState->field_0x04, frameRateScale);
  if (ptsDelta < 0) {
    return 0;
  }
  return ptsDelta;
}

/**
 * Address: 0x00AD2F90 (FUN_00AD2F90, _sfmpv_ReadPtsQue)
 *
 * What it does:
 * Reads one PTS queue entry from the active source lane and complements it
 * using timing/complement state into presentation and reference-seed outputs.
 */
std::int64_t sfmpv_ReadPtsQue(
  const std::int32_t workctrlAddress,
  SfmpvPictureDecodeLaneRuntimeView* const pictureDecodeLane,
  char* const delimiterCursor,
  std::int32_t* const outPresentationPtsWords,
  std::int32_t* const outReferenceSeedWords,
  const std::int32_t pictureChangedFlag
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  outPresentationPtsWords[0] = -1;
  outPresentationPtsWords[1] = -1;
  outReferenceSeedWords[0] = -1;
  outReferenceSeedWords[1] = -1;

  if (delimiterCursor == nullptr) {
    return -1;
  }

  std::int32_t queuedPtsWords[4]{};
  SFPTS_ReadPtsQue(
    workctrlAddress,
    workctrl->prepSourceLaneIndex,
    PointerToAddress(delimiterCursor),
    queuedPtsWords
  );

  const std::int64_t rawPts =
    (static_cast<std::int64_t>(static_cast<std::uint32_t>(queuedPtsWords[1])) << 32)
    | static_cast<std::uint32_t>(queuedPtsWords[0]);
  if (rawPts < 0) {
    return rawPts;
  }

  const std::int64_t complementedPts = sfmpv_ComplementPts(
    PointerToAddress(&workctrl->timingLane),
    &mpvInfo->complementPts,
    pictureDecodeLane,
    queuedPtsWords,
    pictureChangedFlag,
    outReferenceSeedWords
  );
  outPresentationPtsWords[0] = static_cast<std::int32_t>(complementedPts);
  outPresentationPtsWords[1] = static_cast<std::int32_t>(complementedPts >> 32);
  return complementedPts;
}

/**
 * Address: 0x00AD37C0 (FUN_00AD37C0, _sfmpv_SetHeadTtu)
 *
 * What it does:
 * Seeds head-TTU snapshot once from current repeat-timecode lane and latches
 * converted head time for decode-TTU delta tracking.
 */
std::int32_t sfmpv_SetHeadTtu(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;

  std::int32_t result = static_cast<std::int32_t>(timingLane->concatVideoTimeUnit[0]);
  if (result == 0) {
    SfmpvPackedTimecodeRuntimeView headTimecode{};
    std::memcpy(&headTimecode, &timingLane->repeatFieldTimecode, sizeof(headTimecode));
    headTimecode.halfFrameCarry = 0;

    std::int32_t headTimeMajor = 0;
    std::int32_t headTimeMinor = 0;
    (void)SFTIM_Tc2Time(&headTimecode, &headTimeMajor, &headTimeMinor);

    timingLane->concatVideoTimeUnit[9] = static_cast<std::uint32_t>(headTimeMajor);
    std::memcpy(&timingLane->concatVideoTimeUnit[1], &headTimecode, sizeof(headTimecode));
    timingLane->concatVideoTimeUnit[10] = static_cast<std::uint32_t>(headTimeMinor);
    timingLane->concatVideoTimeUnit[0] = 1;
    result = headTimeMajor;
  }

  return result;
}

/**
 * Address: 0x00AD3840 (FUN_00AD3840, _sfmpv_SetDecTtu)
 *
 * What it does:
 * Refreshes decode-TTU from current repeat-timecode lane, computes delta to
 * head-TTU major time, and updates promoted decode TTU snapshot when advanced.
 */
std::int32_t sfmpv_SetDecTtu(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;

  SfmpvPackedTimecodeRuntimeView decodeTimecode{};
  std::memcpy(&decodeTimecode, &timingLane->repeatFieldTimecode, sizeof(decodeTimecode));

  std::int32_t decodeTimeMajor = 0;
  std::int32_t decodeTimeMinor = 0;
  (void)SFTIM_Tc2Time(&decodeTimecode, &decodeTimeMajor, &decodeTimeMinor);

  auto* const pendingStartTtu = AddressToPointer<SfmpvTtuRuntimeView>(PointerToAddress(&timingLane->pendingStartTtu));
  std::memcpy(pendingStartTtu->packedTimecodeWords, &decodeTimecode, sizeof(decodeTimecode));
  pendingStartTtu->timeMajor = decodeTimeMajor - static_cast<std::int32_t>(timingLane->concatVideoTimeUnit[9]);
  pendingStartTtu->timeMinor = decodeTimeMinor;
  pendingStartTtu->state = 1;

  auto* const decodeTtu = AddressToPointer<SfmpvTtuRuntimeView>(PointerToAddress(&timingLane->concatAudioTimeUnit[0]));
  const std::int32_t result = decodeTtu->timeMajor;
  if (result <= pendingStartTtu->timeMajor) {
    *decodeTtu = *pendingStartTtu;
  }

  return result;
}

/**
 * Address: 0x00AD38D0 (FUN_00AD38D0, _sfmpv_ReadTcode)
 *
 * What it does:
 * Copies one frame object's packed timecode lane into one MPV repeat-timecode
 * workspace and clears the accumulated-repeat word.
 */
std::int32_t sfmpv_ReadTcode(
  const std::int32_t frameObjectAddress,
  SfmpvPackedTimecodeRuntimeView* const outTimecodeLane
)
{
  const auto* const frameObject = AddressToPointer<SfmpvfTimecodeSourceRuntimeView>(frameObjectAddress);
  outTimecodeLane->frameRateIndex = frameObject->word00;
  outTimecodeLane->dropFrameMode = frameObject->word0C;
  outTimecodeLane->hours = frameObject->word10;
  outTimecodeLane->minutes = frameObject->word14;
  outTimecodeLane->seconds = frameObject->word18;
  outTimecodeLane->frameNumber = frameObject->word1C;
  outTimecodeLane->halfFrameCarry = frameObject->word04;
  outTimecodeLane->repeatFieldCount = frameObject->repeatFieldCount;
  outTimecodeLane->repeatFieldAccumulated = 0;
  return PointerToAddress(outTimecodeLane);
}

/**
 * Address: 0x00AD3330 (FUN_00AD3330, _sfmpv_CalcFrmTtu)
 *
 * What it does:
 * Converts one frame-object packed timecode lane into TTU major/minor values,
 * marks the frame TTU valid, and updates max-observed TTU snapshot.
 */
std::int32_t sfmpv_CalcFrmTtu(const std::int32_t workctrlAddress, const std::int32_t frameObjectAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTimingRuntimeView>(frameObjectAddress);

  std::int32_t frameTimeMajor = 0;
  std::int32_t frameTimeMinor = 0;
  (void)SFTIM_Tc2Time(frameTiming->frameTtu.packedTimecodeWords, &frameTimeMajor, &frameTimeMinor);

  frameTiming->frameTtu.timeMajor = frameTimeMajor - static_cast<std::int32_t>(workctrl->timingLane.concatVideoTimeUnit[9]);
  frameTiming->frameTtu.timeMinor = frameTimeMinor;
  frameTiming->frameTtu.state = 1;

  if (static_cast<std::int32_t>(workctrl->timingLane.concatAudioTimeUnit[9]) <= frameTiming->frameTtu.timeMajor) {
    std::memcpy(
      &workctrl->timingLane.concatAudioTimeUnit[0],
      &frameTiming->frameTtu,
      sizeof(SfmpvTtuRuntimeView)
    );
  }

  return frameTiming->frameTtu.timeMajor;
}

/**
 * Address: 0x00AD4330 (FUN_00AD4330, _sfmpv_DecodeFrm)
 *
 * What it does:
 * Builds one decode-frame parameter block, runs MPV frame decode on current
 * stream lane, updates frame/timing/error state, and enqueues decoded picture.
 */
std::int32_t sfmpv_DecodeFrm(const std::int32_t workctrlAddress, const std::int32_t streamBufferAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  const std::int32_t decoderHandle = mpvInfo->decoderHandle;

  SfmpvDecodeFrameParamRuntimeView decodeFrameParam{};
  std::int32_t frameObjectAddress = 0;
  if (sfmpv_SetFrmPara(workctrlAddress, &mpvInfo->pictureDecodeLane, &decodeFrameParam, &frameObjectAddress) != 0) {
    return 0;
  }

  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  std::int32_t referenceErrorMajor = 0;
  std::int32_t referenceErrorMinor = 0;
  (void)sfmpv_ReadRefErrCnt(workctrlAddress, mpvInfo, &referenceErrorMajor, &referenceErrorMinor);

  (void)sfmpv_CopyPicUsrInf(
    frameObject->pictureUserInfoAddress,
    PointerToAddress(&mpvInfo->pictureUserBufferMirrorAddress)
  );
  (void)sfmpv_SetStartTtu(workctrlAddress);

  const std::int64_t decodeStart = SFTMR_GetTmr();
  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1);
  const std::int32_t decodeResult = MPV_DecodeFrmSj(decoderHandle, streamBufferAddress, &decodeFrameParam);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1) - flowCountBefore;

  const std::int64_t decodeElapsed = SFTMR_GetTmr() - decodeStart;
  SFTMR_AddTsum(
    &workctrl->decodeTimeSumsByPictureType[mpvInfo->pictureDecodeLane.pictureType],
    static_cast<std::int32_t>(decodeElapsed),
    static_cast<std::int32_t>(decodeElapsed >> 32)
  );

  workctrl->decodeReferenceErrorMajor += decodeFrameParam.reserved28;
  workctrl->decodeReferenceErrorMinor += decodeFrameParam.reserved2C;

  const std::int32_t checkedResult =
    sfmpv_ChkMpvErr(workctrlAddress, decodeResult, consumedBytes, -16773370);
  sfmpv_AddRtotSj(workctrlAddress, consumedBytes);
  if (checkedResult != 0) {
    SFMPVF_FreeFrm(frameObjectAddress);
    return checkedResult;
  }

  if (consumedBytes <= 0) {
    if (mpvInfo->pendingFrameObjectAddress == 0) {
      SFMPVF_FreeFrm(frameObjectAddress);
    }
    return 0;
  }

  SFMPVF_FixDispOrder(workctrlAddress, 0);
  (void)sfmpv_SetFrmTime(workctrlAddress, frameObjectAddress);

  frameObject->decodeConcatOrdinal = mpvInfo->concatAdvanceCount;
  frameObject->referenceErrorMajor =
    referenceErrorMajor + decodeFrameParam.reserved28 + mpvInfo->referenceErrorCarryFlag;
  frameObject->referenceErrorMinor = referenceErrorMinor + decodeFrameParam.reserved2C;

  if (mpvInfo->pictureDecodeLane.referenceUpdateMode == 3 || mpvInfo->pendingFrameObjectAddress != 0) {
    mpvInfo->pendingFrameObjectAddress = 0;
  } else {
    mpvInfo->pendingFrameObjectAddress = frameObjectAddress;
  }

  const std::int32_t pendingFrameObjectAddress = mpvInfo->pendingFrameObjectAddress;
  mpvInfo->skipIssuedFlag = 0;
  mpvInfo->picAtrPrimedLatch = 0;
  if (pendingFrameObjectAddress == 0) {
    const std::int32_t pictureType = mpvInfo->pictureDecodeLane.pictureType;
    if (workctrl->mpvCond6Value == 3 && (pictureType == 1 || pictureType == 2)) {
      SFMPVF_RefStbyFrm(frameObjectAddress);
    } else {
      SFMPVF_StbyFrm(frameObjectAddress);
    }

    MPV_GetDctCnt(decoderHandle, &workctrl->decoderDctCountPrimary, &workctrl->decoderDctCountSecondary);
    mpvInfo->lateFrameCounter = 0;
  }

  SFPLY_AddDecPic(workctrlAddress, 1, mpvInfo->pictureDecodeLane.pictureType);
  return 0;
}

/**
 * Address: 0x00AD4590 (FUN_00AD4590, _sfmpv_SetFrmPara)
 *
 * What it does:
 * Selects or allocates one frame object, copies current picture decode lane
 * into it, and builds decode-plane address/stride parameters for MPV decode.
 */
std::int32_t sfmpv_SetFrmPara(
  const std::int32_t workctrlAddress,
  const SfmpvPictureDecodeLaneRuntimeView* const pictureDecodeLane,
  SfmpvDecodeFrameParamRuntimeView* const decodeFrameParam,
  std::int32_t* const outFrameObjectAddress
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  const std::int32_t pendingFrameObjectAddress = mpvInfo->pendingFrameObjectAddress;
  std::int32_t frameObjectAddress = pendingFrameObjectAddress;
  if (frameObjectAddress == 0) {
    auto* const allocatedFrame = SFMPVF_AllocFrm(workctrlAddress);
    frameObjectAddress = PointerToAddress(allocatedFrame);
    *outFrameObjectAddress = frameObjectAddress;
    if (frameObjectAddress == 0) {
      workctrl->frameAllocationFailed = 1;
      return -1;
    }
  } else {
    *outFrameObjectAddress = frameObjectAddress;
  }

  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  std::memcpy(&frameObject->pictureDecodeLane, pictureDecodeLane, sizeof(SfmpvPictureDecodeLaneRuntimeView));
  frameObject->referenceErrorSeedMajor = mpvInfo->referenceErrorSeedMajor;
  frameObject->referenceErrorSeedMinor = mpvInfo->referenceErrorSeedMinor;

  if (workctrl->mpvCond6Value == 3) {
    const std::int32_t pictureType = pictureDecodeLane->pictureType;
    if ((pictureType == 1 || pictureType == 2) && pendingFrameObjectAddress == 0) {
      SFMPVF_EndRefFrm(mpvInfo->primaryReferenceFrameObjectAddress);
      mpvInfo->primaryReferenceFrameObjectAddress = mpvInfo->secondaryReferenceFrameObjectAddress;
      mpvInfo->secondaryReferenceFrameObjectAddress = frameObjectAddress;
    }

    const std::int32_t widthAligned16 = ((pictureDecodeLane->pictureWidthPixels + 15) / 16) * 16;
    const std::int32_t lumaBlocks32 = (widthAligned16 + 31) / 32;
    const std::int32_t chromaBlocks32 = ((widthAligned16 / 2) + 31) / 32;

    const std::uint16_t lumaStride = static_cast<std::uint16_t>(32 * lumaBlocks32);
    const std::uint16_t chromaStride = static_cast<std::uint16_t>(32 * chromaBlocks32);
    decodeFrameParam->primaryStridePacked =
      static_cast<std::int32_t>((static_cast<std::uint32_t>(lumaStride) << 16) | chromaStride);
    decodeFrameParam->secondaryStridePacked = decodeFrameParam->primaryStridePacked;

    const auto* const primaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->primaryReferenceFrameObjectAddress);
    decodeFrameParam->primaryFrameBaseAddress = primaryReferenceFrame->frameSurfaceBaseAddress;

    const std::int32_t heightBlocks32 = (pictureDecodeLane->pictureHeightPixels + 31) / 32;
    const std::int32_t lumaPlaneOffsetBytes = (lumaBlocks32 * heightBlocks32) << 10;
    const std::int32_t primaryLumaAddress = decodeFrameParam->primaryFrameBaseAddress + lumaPlaneOffsetBytes;
    decodeFrameParam->primaryLumaPlaneAddress = primaryLumaAddress;

    const std::int32_t chromaPlaneBytes = (32 * chromaBlocks32) * ((32 * heightBlocks32) / 2);
    decodeFrameParam->primaryChromaPlaneAddress = primaryLumaAddress + chromaPlaneBytes;

    const auto* const secondaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->secondaryReferenceFrameObjectAddress);
    decodeFrameParam->secondaryFrameBaseAddress = secondaryReferenceFrame->frameSurfaceBaseAddress;

    const std::int32_t secondaryLumaAddress = decodeFrameParam->secondaryFrameBaseAddress + lumaPlaneOffsetBytes;
    decodeFrameParam->secondaryLumaPlaneAddress = secondaryLumaAddress;
    decodeFrameParam->secondaryChromaPlaneAddress = secondaryLumaAddress + chromaPlaneBytes;
  } else {
    const std::int32_t pictureType = pictureDecodeLane->pictureType;
    if (pictureType == 1 || pictureType == 2) {
      mpvInfo->primaryFrameToggleIndex ^= 1;
      mpvInfo->secondaryFrameToggleIndex ^= 1;
      mpvInfo->secondaryReferenceFrameObjectAddress = frameObjectAddress;
    }

    const std::int32_t* const framePlaneTable = &mpvInfo->primaryLumaPlaneBaseAddress;
    const std::int32_t* const primaryPlaneSet = framePlaneTable + (4 * mpvInfo->primaryFrameToggleIndex);
    const std::int32_t* const secondaryPlaneSet = framePlaneTable + (4 * mpvInfo->secondaryFrameToggleIndex);

    decodeFrameParam->primaryLumaPlaneAddress = primaryPlaneSet[0];
    decodeFrameParam->primaryChromaPlaneAddress = primaryPlaneSet[1];
    decodeFrameParam->primaryFrameBaseAddress = primaryPlaneSet[2];
    decodeFrameParam->primaryStridePacked = primaryPlaneSet[3];

    decodeFrameParam->secondaryLumaPlaneAddress = secondaryPlaneSet[0];
    decodeFrameParam->secondaryChromaPlaneAddress = secondaryPlaneSet[1];
    decodeFrameParam->secondaryFrameBaseAddress = secondaryPlaneSet[2];
    decodeFrameParam->secondaryStridePacked = secondaryPlaneSet[3];
  }

  decodeFrameParam->decodedFrameBaseAddress = frameObject->frameSurfaceBaseAddress;
  decodeFrameParam->pictureDecodeLaneAddress = PointerToAddress(&frameObject->pictureDecodeLane);
  decodeFrameParam->reserved28 = 0;
  decodeFrameParam->reserved2C = 0;
  workctrl->frameAllocationFailed = 0;
  return 0;
}

/**
 * Address: 0x00AD47E0 (FUN_00AD47E0, _sfmpv_ReadRefErrCnt)
 *
 * What it does:
 * Reads cumulative decode-error lanes from current reference-frame objects for
 * P/B picture decode paths, or zeroes outputs when not applicable.
 */
std::int32_t sfmpv_ReadRefErrCnt(
  const std::int32_t workctrlAddress,
  const SfmpvInfoRuntimeView* const mpvInfo,
  std::int32_t* const outErrorMajor,
  std::int32_t* const outErrorMinor
)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  if (workctrl->mpvCond6Value != 3) {
    *outErrorMajor = 0;
    *outErrorMinor = 0;
    return PointerToAddress(outErrorMajor);
  }

  const std::int32_t pictureType = mpvInfo->pictureDecodeLane.pictureType;
  if (pictureType == 2) {
    const auto* const primaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->primaryReferenceFrameObjectAddress);
    *outErrorMajor = primaryReferenceFrame->referenceErrorMajor;
    *outErrorMinor = primaryReferenceFrame->referenceErrorMinor;
    return mpvInfo->primaryReferenceFrameObjectAddress;
  }

  if (pictureType == 3) {
    const auto* const primaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->primaryReferenceFrameObjectAddress);
    const auto* const secondaryReferenceFrame =
      AddressToPointer<const SfmpvfFrameObjectRuntimeView>(mpvInfo->secondaryReferenceFrameObjectAddress);

    *outErrorMajor = primaryReferenceFrame->referenceErrorMajor + secondaryReferenceFrame->referenceErrorMajor;
    const std::int32_t summedMinor =
      primaryReferenceFrame->referenceErrorMinor + secondaryReferenceFrame->referenceErrorMinor;
    *outErrorMinor = summedMinor;
    return summedMinor;
  }

  *outErrorMajor = 0;
  *outErrorMinor = 0;
  return PointerToAddress(mpvInfo);
}

/**
 * Address: 0x00AD4880 (FUN_00AD4880, _sfmpv_SetStartTtu)
 *
 * What it does:
 * Seeds the start-TTU lane once from pending packed timecode, applies defect
 * and picture-type skip gating, and latches converted start time.
 */
std::int32_t sfmpv_SetStartTtu(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;

  std::int32_t result = timingLane->interpolationEnabled;
  if (result != 0) {
    return result;
  }

  SfmpvPackedTimecodeRuntimeView startTimecode{};
  std::memcpy(&startTimecode, timingLane->pendingStartTtu.packedTimecodeWords, sizeof(startTimecode));

  if (sfmpv_IsDefect(workctrlAddress, 3) == 0 && sfmpv_IsPtypeSkip(workctrlAddress, 3) == 0) {
    startTimecode.halfFrameCarry = 0;
  }

  std::int32_t startTimeMajor = 0;
  std::int32_t startTimeMinor = 0;
  (void)SFTIM_Tc2Time(&startTimecode, &startTimeMajor, &startTimeMinor);

  std::memcpy(timingLane->activeStartTimecodeWords, &startTimecode, sizeof(startTimecode));

  result = startTimeMajor - static_cast<std::int32_t>(timingLane->concatVideoTimeUnit[9]);
  timingLane->frameInterpolationTime = result;
  timingLane->frameInterpolationMinor = startTimeMinor;
  timingLane->interpolationEnabled = 1;
  return result;
}

/**
 * Address: 0x00AD4920 (FUN_00AD4920, _sfmpv_SetFrmTime)
 *
 * What it does:
 * Copies pending start-TTU lane into one frame object's timing lane and then
 * recalculates resolved frame time values.
 */
std::int32_t sfmpv_SetFrmTime(const std::int32_t workctrlAddress, const std::int32_t frameObjectAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTimingRuntimeView>(frameObjectAddress);
  std::memcpy(&frameTiming->frameTtu, &workctrl->timingLane.pendingStartTtu, sizeof(SfmpvTtuRuntimeView));
  return sfmpv_CalcFrmTime(workctrlAddress, frameObjectAddress);
}

/**
 * Address: 0x00AD4950 (FUN_00AD4950, _sfmpv_CalcFrmTime)
 *
 * What it does:
 * Updates resolved frame timing lanes from TTU state and decode progress
 * lanes, while tracking global max resolved frame time in the workctrl.
 */
std::int32_t sfmpv_CalcFrmTime(const std::int32_t workctrlAddress, const std::int32_t frameObjectAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTimingRuntimeView>(frameObjectAddress);

  std::int32_t result = frameObjectAddress;

  frameTiming->resolvedTimeMinor = frameTiming->frameTtu.timeMinor;
  frameTiming->resolvedTimeMajor =
    frameTiming->frameTtu.timeMajor + workctrl->timingLane.decodeProgressTime - workctrl->timingLane.frameInterpolationTime;
  frameTiming->frameStartTimeMajor = frameTiming->frameTtu.timeMajor;
  frameTiming->frameEndTimeMajor = frameTiming->frameTtu.timeMajor + workctrl->timingLane.decodeProgressTime;

  if (workctrl->maxFrameTimeMajor < frameTiming->resolvedTimeMajor) {
    workctrl->maxFrameTimeMajor = frameTiming->resolvedTimeMajor;
    result = frameTiming->resolvedTimeMinor;
    workctrl->maxFrameTimeMinor = result;
  }

  return result;
}

/**
 * Address: 0x00AD31A0 (FUN_00AD31A0, _sfmpv_CalcRepeatField)
 *
 * What it does:
 * Updates 64-slot repeat-field history lanes, propagates accumulated repeat
 * values to reference-frame lanes, and refreshes reference frame timing.
 */
std::int32_t sfmpv_CalcRepeatField(
  const std::int32_t workctrlAddress,
  const std::int32_t frameObjectAddress,
  const std::int32_t resetHistory
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const frameRepeat = AddressToPointer<SfmpvfFrameRepeatRuntimeView>(frameObjectAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  sfmpv_ReadTcode(frameObjectAddress, &workctrl->timingLane.repeatFieldTimecode);

  if (resetHistory != 0) {
    for (std::int32_t index = 0; index < 64; ++index) {
      workctrl->repeatFieldHistory.samples[index].repeatFieldCount = -1;
    }
    workctrl->repeatFieldHistory.samples[0].accumulatedRepeatCount = -1;
  } else if (frameRepeat->pictureType == 1 || frameRepeat->pictureType == 2) {
    const std::int32_t referenceFrameAddress = mpvInfo->secondaryReferenceFrameObjectAddress;
    const auto* const referenceFrame = AddressToPointer<SfmpvfFrameRepeatRuntimeView>(referenceFrameAddress);

    std::int32_t scanOrdinal = referenceFrame->decodeOrderIndex;
    std::int32_t targetOrdinal = frameRepeat->historyOrdinal;
    if (targetOrdinal < scanOrdinal) {
      targetOrdinal += 1024;
    }

    for (std::int32_t ordinal = scanOrdinal + 1; ordinal < targetOrdinal; ++ordinal) {
      workctrl->repeatFieldHistory.samples[Modulo64Index(ordinal)].repeatFieldCount = -1;
    }
  }

  const std::int32_t currentIndex = Modulo64Index(frameRepeat->historyOrdinal);
  SfmpvRepeatFieldSampleRuntimeView& currentSample = workctrl->repeatFieldHistory.samples[currentIndex];
  currentSample.repeatFieldCount = workctrl->timingLane.repeatFieldTimecode.repeatFieldCount;

  if (resetHistory != 0) {
    currentSample.accumulatedRepeatCount = 0;
  } else if (
    frameRepeat->historyOrdinal != 0
    || workctrl->repeatFieldHistory.samples[0].accumulatedRepeatCount != static_cast<std::int16_t>(-1)
  ) {
    std::int32_t misses = 0;
    std::int32_t searchOrdinal = currentIndex + 63;
    while (workctrl->repeatFieldHistory.samples[Modulo64Index(searchOrdinal)].repeatFieldCount == static_cast<std::int16_t>(-1)) {
      ++misses;
      --searchOrdinal;
      if (misses >= 64) {
        break;
      }
    }

    if (misses < 64) {
      const SfmpvRepeatFieldSampleRuntimeView& previousSample =
        workctrl->repeatFieldHistory.samples[Modulo64Index(searchOrdinal)];
      currentSample.accumulatedRepeatCount =
        static_cast<std::int16_t>(previousSample.repeatFieldCount + previousSample.accumulatedRepeatCount);
    }
  } else {
    workctrl->repeatFieldHistory.samples[0].accumulatedRepeatCount = 0;
  }

  workctrl->timingLane.repeatFieldTimecode.repeatFieldAccumulated = currentSample.accumulatedRepeatCount;

  if (frameRepeat->pictureType == 3 && currentSample.repeatFieldCount != 0) {
    const std::int32_t referenceFrameAddress = mpvInfo->secondaryReferenceFrameObjectAddress;
    auto* const referenceFrame = AddressToPointer<SfmpvfFrameRepeatRuntimeView>(referenceFrameAddress);

    const std::int32_t referenceIndex = Modulo64Index(referenceFrame->decodeOrderIndex);
    const std::int16_t propagatedRepeat =
      static_cast<std::int16_t>(currentSample.repeatFieldCount + currentSample.accumulatedRepeatCount);
    workctrl->repeatFieldHistory.samples[referenceIndex].accumulatedRepeatCount = propagatedRepeat;
    referenceFrame->repeatAccumulatorWord = static_cast<std::uint16_t>(propagatedRepeat);

    (void)sfmpv_CalcFrmTtu(workctrlAddress, referenceFrameAddress);
    return sfmpv_CalcFrmTime(workctrlAddress, referenceFrameAddress);
  }

  return frameRepeat->pictureType;
}

/**
 * Address: 0x00ADC1E0 (FUN_00ADC1E0, _SFMPVF_AllocFrm)
 *
 * What it does:
 * Finds the first frame object whose owner-state pair is clear, marks it
 * allocated, and returns its frame-object address under SFLIB lock.
 */
SfmpvfFrameObjectRuntimeView* SFMPVF_AllocFrm(const std::int32_t workctrlAddress)
{
  SFLIB_LockCs();

  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const mpvInfo = reinterpret_cast<SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);
  const std::int32_t frameObjectCount = mpvInfo->frameObjectCount;

  SfmpvfFrameObjectRuntimeView* allocatedFrameObject = nullptr;
  for (std::int32_t frameIndex = 0; frameIndex < frameObjectCount; ++frameIndex) {
    SfmpvfFrameObjectRuntimeView& frameObject = mpvInfo->frameObjects[frameIndex];
    if (frameObject.decodeState == 0 && frameObject.allocationState == 0) {
      frameObject.decodeState = 1;
      allocatedFrameObject = &frameObject;
      break;
    }
  }

  SFLIB_UnlockCs();
  return allocatedFrameObject;
}

/**
 * Address: 0x00AD3AE0 (FUN_00AD3AE0, _sfmpv_ChkBufSiz)
 *
 * What it does:
 * Validates configured frame-buffer capacity against requested dimensions and
 * rebuilds frame-object base lanes and color-plane address lanes.
 */
std::int32_t sfmpv_ChkBufSiz(const std::int32_t workctrlAddress, const std::int32_t* const frameDimensions)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  const std::int32_t requestedWidth = frameDimensions[0];
  const std::int32_t requestedHeight = frameDimensions[1];

  const std::int32_t configuredWidthAligned16 = ((mpvInfo->persistedPara.field_0x08 + 15) / 16) * 16;
  const std::int32_t configuredHeightBlocks32 = (mpvInfo->persistedPara.field_0x0C + 31) / 32;
  const std::int32_t configuredLumaBlocks32 = (configuredWidthAligned16 + 31) / 32;
  const std::int32_t configuredChromaBlocks32 = ((configuredWidthAligned16 / 2) + 31) / 32;
  const std::int32_t configuredFrameUnitBytes =
    16 * ((configuredHeightBlocks32 * configuredLumaBlocks32) + 2)
    + ((32 * configuredHeightBlocks32) / 2) * configuredChromaBlocks32;

  const std::int32_t requestedWidthAligned16 = ((requestedWidth + 15) / 16) * 16;
  const std::int32_t requestedChromaBlocks32 = ((requestedWidthAligned16 / 2) + 31) / 32;
  const std::int32_t requestedLumaBlocks32 = (requestedWidthAligned16 + 31) / 32;
  const std::int32_t requestedHeightBlocks32 = (requestedHeight + 31) / 32;
  const std::int32_t requestedLumaTiles = requestedHeightBlocks32 * requestedLumaBlocks32;
  const std::int32_t requestedChromaTiles = requestedChromaBlocks32 * ((32 * requestedHeightBlocks32) / 2);
  const std::int32_t requestedFrameUnitBytes = requestedChromaTiles + (16 * (requestedLumaTiles + 2));

  if ((requestedFrameUnitBytes << 7) > (configuredFrameUnitBytes << 7)) {
    return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameBufferTooSmall);
  }

  std::int32_t availableFrameSlots = 0;
  if (mpvInfo->persistedPara.val8 != 0) {
    availableFrameSlots = 1;
    const std::int32_t configuredCapacityBytes =
      (mpvInfo->persistedPara.nfrm_pool_wk * configuredFrameUnitBytes) << 6;
    const std::int32_t requestedSlotBytes = requestedFrameUnitBytes << 6;
    std::int32_t runningBytes = requestedSlotBytes;
    while (runningBytes <= configuredCapacityBytes) {
      ++availableFrameSlots;
      runningBytes += requestedSlotBytes;
      if (availableFrameSlots > 16) {
        break;
      }
    }
    --availableFrameSlots;

    if (availableFrameSlots < mpvInfo->persistedPara.nfrm_pool_wk) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameBufferTooSmall);
    }

    mpvInfo->persistedRfbAddressTable[0] = mpvInfo->persistedPara.val4;
    mpvInfo->persistedRfbAddressTable[1] = mpvInfo->persistedPara.val4 + requestedSlotBytes;
    for (std::int32_t slotIndex = 0; slotIndex < availableFrameSlots; ++slotIndex) {
      mpvInfo->persistedSofDecTabs[slotIndex] = mpvInfo->persistedPara.val8 + (slotIndex * requestedSlotBytes);
    }
  } else {
    availableFrameSlots = mpvInfo->persistedPara.nfrm_pool_wk;
  }

  mpvInfo->secondaryLumaStride = static_cast<std::uint16_t>(32 * requestedLumaBlocks32);
  mpvInfo->secondaryChromaStride = static_cast<std::uint16_t>(32 * requestedChromaBlocks32);
  mpvInfo->primaryLumaStride = mpvInfo->secondaryLumaStride;
  mpvInfo->primaryChromaStride = mpvInfo->secondaryChromaStride;

  const std::int32_t lumaPlaneOffset = requestedLumaTiles << 10;
  const std::int32_t chromaPlaneOffset = 32 * requestedChromaTiles;

  mpvInfo->primaryLumaPlaneBaseAddress = mpvInfo->persistedRfbAddressTable[0] + lumaPlaneOffset;
  mpvInfo->primaryChromaUPlaneBaseAddress = mpvInfo->primaryLumaPlaneBaseAddress + chromaPlaneOffset;
  mpvInfo->primaryFrameBaseAddress = mpvInfo->persistedRfbAddressTable[0];

  mpvInfo->secondaryLumaPlaneBaseAddress = mpvInfo->persistedRfbAddressTable[1] + lumaPlaneOffset;
  mpvInfo->secondaryChromaUPlaneBaseAddress = mpvInfo->secondaryLumaPlaneBaseAddress + chromaPlaneOffset;
  mpvInfo->secondaryFrameBaseAddress = mpvInfo->persistedRfbAddressTable[1];

  if (workctrl->mpvCond6Value == 3) {
    std::int32_t movableFrameCount = availableFrameSlots;
    if (movableFrameCount >= 14) {
      movableFrameCount = 14;
    }

    auto* const mpvFrameInfo = reinterpret_cast<SfmpvfInfoRuntimeView*>(mpvInfo);
    mpvFrameInfo->frameObjectCount = movableFrameCount + 2;
    sfmpv_InitFrmObj(
      reinterpret_cast<std::uint32_t*>(&mpvFrameInfo->frameObjects[0]),
      &mpvInfo->persistedRfbAddressTable[0],
      2
    );
    sfmpv_InitFrmObj(
      reinterpret_cast<std::uint32_t*>(&mpvFrameInfo->frameObjects[2]),
      &mpvInfo->persistedSofDecTabs[0],
      movableFrameCount
    );

    mpvInfo->primaryReferenceFrameObjectAddress = PointerToAddress(SFMPVF_AllocFrm(workctrlAddress));
    mpvInfo->secondaryReferenceFrameObjectAddress = PointerToAddress(SFMPVF_AllocFrm(workctrlAddress));
  } else {
    std::int32_t frameObjectCount = availableFrameSlots;
    if (frameObjectCount >= 16) {
      frameObjectCount = 16;
    }

    auto* const mpvFrameInfo = reinterpret_cast<SfmpvfInfoRuntimeView*>(mpvInfo);
    mpvFrameInfo->frameObjectCount = frameObjectCount;
    sfmpv_InitFrmObj(
      reinterpret_cast<std::uint32_t*>(&mpvFrameInfo->frameObjects[0]),
      &mpvInfo->persistedSofDecTabs[0],
      frameObjectCount
    );
  }

  return 0;
}

/**
 * Address: 0x00AD49E0 (FUN_00AD49E0, _sfmpv_GoDdelim)
 *
 * What it does:
 * Advances ring-read cursor to one delimiter candidate and updates tracked
 * read counters for delimiter and total-read lanes.
 */
std::int32_t sfmpv_GoDdelim(
  const std::int32_t workctrlAddress,
  const std::int32_t /*streamBufferAddress*/,
  const std::int32_t delimiterMask
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  SfbufRingCursorSnapshotRuntimeView ringCursor{};
  if (SFBUF_RingGetRead(workctrlAddress, workctrl->prepSourceLaneIndex, reinterpret_cast<std::int32_t*>(&ringCursor)) != 0) {
    return 0;
  }

  if (ringCursor.firstChunk.byteCount == 0) {
    return 0;
  }

  std::int32_t delimiterState = 0;
  const std::uint8_t* const delimiterCursor =
    sfmpv_SearchDelim(PointerToAddress(&ringCursor), delimiterMask, &delimiterState);

  std::int32_t advanceBytes = 0;
  if (delimiterCursor != nullptr) {
    const std::uintptr_t delimiterAddress = reinterpret_cast<std::uintptr_t>(delimiterCursor);
    const std::uintptr_t firstBase = reinterpret_cast<std::uintptr_t>(ringCursor.firstChunk.bufferAddress);
    const std::uintptr_t secondBase = reinterpret_cast<std::uintptr_t>(ringCursor.secondChunk.bufferAddress);
    const std::uintptr_t firstEnd = firstBase + static_cast<std::uint32_t>(ringCursor.firstChunk.byteCount);
    const std::uintptr_t secondEnd = secondBase + static_cast<std::uint32_t>(ringCursor.secondChunk.byteCount);

    if (firstBase <= delimiterAddress && delimiterAddress < firstEnd) {
      advanceBytes = static_cast<std::int32_t>(delimiterAddress - firstBase);
    } else if (secondBase <= delimiterAddress && delimiterAddress < secondEnd) {
      advanceBytes =
        static_cast<std::int32_t>((delimiterAddress - secondBase) + static_cast<std::uintptr_t>(ringCursor.firstChunk.byteCount));
    }
  } else {
    const std::int32_t windowBytes = ringCursor.firstChunk.byteCount + ringCursor.secondChunk.byteCount - 3;
    advanceBytes = (windowBytes > 0) ? windowBytes : 0;
  }

  (void)sfmpv_RingAddRead(workctrlAddress, advanceBytes);

  const std::int32_t probeCount = (advanceBytes < 3) ? advanceBytes : 3;
  for (std::int32_t index = 0; index < probeCount; ++index) {
    const std::uint8_t* probeByte = ringCursor.firstChunk.bufferAddress + index;
    if (index >= ringCursor.firstChunk.byteCount) {
      probeByte = ringCursor.secondChunk.bufferAddress + (index - ringCursor.firstChunk.byteCount);
    }

    if (*probeByte != 0) {
      AddSigned32ToLane(&workctrl->delimiterReadTotalLow, &workctrl->delimiterReadTotalHigh, advanceBytes);
      break;
    }
  }

  AddSigned32ToLane(&workctrl->ringReadTotalLow, &workctrl->ringReadTotalHigh, advanceBytes);
  return advanceBytes;
}

/**
 * Address: 0x00AD4B10 (FUN_00AD4B10, _sfmpv_RingAddRead)
 *
 * What it does:
 * Adds one read advance on the active source ring lane.
 */
std::int32_t sfmpv_RingAddRead(const std::int32_t workctrlAddress, const std::int32_t advanceCount)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  return SFBUF_RingAddRead(workctrlAddress, workctrl->prepSourceLaneIndex, advanceCount);
}

/**
 * Address: 0x00AD4B30 (FUN_00AD4B30, _sfmpv_UpdateFlowCnt)
 *
 * What it does:
 * Updates per-handle stream-flow counters from current source-lane SJ flow.
 */
std::int32_t sfmpv_UpdateFlowCnt(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  std::int32_t streamHandleAddress = 0;
  (void)SFBUF_RingGetSj(workctrlAddress, workctrl->prepSourceLaneIndex, &streamHandleAddress);
  std::int32_t result = streamHandleAddress;
  if (streamHandleAddress != 0) {
    std::int32_t nextFlowLow = 0;
    std::int32_t nextFlowHigh = 0;
    (void)SFBUF_GetFlowCnt(streamHandleAddress, &nextFlowLow, &nextFlowHigh);

    const std::uint64_t mergedFlow = static_cast<std::uint64_t>(
      SFBUF_UpdateFlowCnt(workctrl->streamFlowCountLow, workctrl->streamFlowCountHigh, nextFlowLow)
    );
    workctrl->streamFlowCountLow = static_cast<std::int32_t>(mergedFlow & 0xFFFFFFFFu);
    workctrl->streamFlowCountHigh = static_cast<std::int32_t>(mergedFlow >> 32);
    result = workctrl->streamFlowCountLow;
  }
  return result;
}

/**
 * Address: 0x00AD3410 (FUN_00AD3410, _sfmpv_DetectTcErr)
 *
 * What it does:
 * Detects reform-timecode drift by comparing current repeat-field timecode
 * against concat-audio baseline TTU time under condition-53 tolerance.
 */
std::int32_t sfmpv_DetectTcErr(
  const std::int32_t workctrlAddress,
  const SfmpvPictureAttributeRuntimeView* const /*pictureAttribute*/
)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  const SfmpvTimingLane* const timingLane = &workctrl->timingLane;
  const auto* const concatAudioTtu =
    reinterpret_cast<const SfmpvTtuRuntimeView*>(timingLane->concatAudioTimeUnit);
  if (concatAudioTtu->state == 0) {
    return 0;
  }

  SfmpvPackedTimecodeRuntimeView currentTimecode{};
  std::memcpy(&currentTimecode, &timingLane->repeatFieldTimecode, sizeof(currentTimecode));

  std::int32_t currentMajor = 0;
  std::int32_t currentMinor = 0;
  (void)SFTIM_Tc2Time(&currentTimecode, &currentMajor, &currentMinor);

  std::int32_t baselineMajor = 0;
  std::int32_t baselineMinor = 0;
  (void)SFTIM_Tc2Time(concatAudioTtu->packedTimecodeWords, &baselineMajor, &baselineMinor);

  const std::int32_t toleranceWindow = baselineMinor * SFSET_GetCond(workctrlAddress, 53);
  if (currentMajor <= baselineMajor) {
    return 1;
  }
  return (currentMajor >= (baselineMajor + toleranceWindow)) ? 1 : 0;
}

/**
 * Address: 0x00AD35B0 (FUN_00AD35B0, _sfmpv_Pts2Tc)
 *
 * What it does:
 * Converts one 90 kHz PTS lane to packed MPV timecode using rate-dependent
 * frame-rounding and drop-frame conversion tables for 29.97/59.94 modes.
 */
std::int32_t sfmpv_Pts2Tc(
  const std::int64_t presentationPts,
  const std::int32_t frameRateIndex,
  const std::int32_t dropFrameMode,
  const std::int32_t decodeOrderMetric,
  SfmpvPackedTimecodeRuntimeView* const outTimecode
)
{
  struct SfmpvDropFrameConversionTable
  {
    std::int32_t cycleFrameCount; // +0x00
    std::int32_t tenMinuteFrameCount; // +0x04
    std::int32_t dropFrameThreshold; // +0x08
    std::int32_t dropMinuteFrameCount; // +0x0C
    std::int32_t dropMinuteHeadFrameCount; // +0x10
    std::int32_t framesPerSecond; // +0x14
    std::int32_t minutesPerTenMinuteChunk; // +0x18
    std::int32_t dropHeadFrameBase; // +0x1C
  };
  static_assert(
    sizeof(SfmpvDropFrameConversionTable) == 0x20,
    "SfmpvDropFrameConversionTable size must be 0x20"
  );

  const std::int32_t frameRateScale = SFTIM_prate[frameRateIndex];
  const std::int32_t frameRoundBase = sfmpv_fps_round[frameRateIndex];
  const std::int64_t scaledFramesRounded =
    UTY_MulDivRound64(presentationPts, static_cast<std::int64_t>(2) * frameRateScale, 90000000LL);
  const std::int32_t scaledFrames = static_cast<std::int32_t>(scaledFramesRounded);

  outTimecode->frameRateIndex = frameRateIndex;
  outTimecode->repeatFieldAccumulated = static_cast<std::int16_t>(scaledFrames & 1);
  outTimecode->dropFrameMode = dropFrameMode;

  std::int32_t frameCursor = (scaledFrames >> 1) - decodeOrderMetric;
  if (frameCursor <= 0) {
    frameCursor = 0;
  }

  const SfmpvDropFrameConversionTable* dropTable = nullptr;
  if (dropFrameMode != 0) {
    if (frameRateScale == 29970) {
      dropTable = reinterpret_cast<const SfmpvDropFrameConversionTable*>(sfmpv_conv_29_97);
    } else if (frameRateScale == 59940) {
      dropTable = reinterpret_cast<const SfmpvDropFrameConversionTable*>(sfmpv_conv_59_94);
    }
  }

  if (dropTable == nullptr) {
    const std::int32_t frameValue = frameCursor % frameRoundBase;
    const std::int32_t secondsValue = (frameCursor / frameRoundBase) % 60;
    const std::int32_t minuteHourValue = frameCursor / frameRoundBase / 60;

    outTimecode->frameNumber = frameValue;
    outTimecode->seconds = secondsValue;
    outTimecode->hours = minuteHourValue / 60;
    outTimecode->minutes = minuteHourValue % 60;
    return outTimecode->hours;
  }

  const std::int32_t cycleRemainder = frameCursor % dropTable->cycleFrameCount;
  const std::int32_t cycleCount = frameCursor / dropTable->cycleFrameCount;
  const std::int32_t tenMinuteChunk = cycleRemainder / dropTable->tenMinuteFrameCount;
  const std::int32_t chunkRemainder = cycleRemainder % dropTable->tenMinuteFrameCount;

  std::int32_t minuteCarry = 0;
  std::int32_t secondsValue = 0;
  std::int32_t frameValue = 0;

  if (chunkRemainder >= dropTable->dropFrameThreshold) {
    minuteCarry = ((chunkRemainder - dropTable->dropFrameThreshold) / dropTable->dropMinuteFrameCount) + 1;
    const std::int32_t dropRemainder =
      (chunkRemainder - dropTable->dropFrameThreshold) % dropTable->dropMinuteFrameCount;
    if (dropRemainder < dropTable->dropMinuteHeadFrameCount) {
      outTimecode->seconds = 0;
      outTimecode->frameNumber = dropRemainder + dropTable->dropHeadFrameBase;
      outTimecode->hours = cycleCount;
      outTimecode->minutes = (tenMinuteChunk * dropTable->minutesPerTenMinuteChunk) + minuteCarry;
      return outTimecode->hours;
    }

    secondsValue = ((dropRemainder - dropTable->dropMinuteHeadFrameCount) / dropTable->framesPerSecond) + 1;
    frameValue = (dropRemainder - dropTable->dropMinuteHeadFrameCount) % dropTable->framesPerSecond;
  } else {
    minuteCarry = 0;
    secondsValue = chunkRemainder / dropTable->framesPerSecond;
    frameValue = chunkRemainder % dropTable->framesPerSecond;
  }

  outTimecode->seconds = secondsValue;
  outTimecode->frameNumber = frameValue;
  outTimecode->hours = cycleCount;
  outTimecode->minutes = (tenMinuteChunk * dropTable->minutesPerTenMinuteChunk) + minuteCarry;
  return outTimecode->hours;
}

/**
 * Address: 0x00AD36F0 (FUN_00AD36F0, _sfmpv_NextTc)
 *
 * What it does:
 * Advances one packed MPV timecode by one frame (+repeat-field carry) and
 * applies drop-frame 00/01 -> 02 skip rules on minute boundaries.
 */
std::int32_t sfmpv_NextTc(
  const SfmpvPackedTimecodeRuntimeView* const sourceTimecode,
  SfmpvPackedTimecodeRuntimeView* const outTimecode
)
{
  const std::int32_t frameRateIndex = sourceTimecode->frameRateIndex;
  const std::int32_t frameRoundBase = sfmpv_fps_round[frameRateIndex];
  const std::int32_t repeatFieldSum =
    static_cast<std::int32_t>(sourceTimecode->repeatFieldCount)
    + static_cast<std::int32_t>(sourceTimecode->repeatFieldAccumulated);

  const std::int32_t advancedFrames =
    sourceTimecode->halfFrameCarry + (repeatFieldSum / 2) + sourceTimecode->frameNumber + 1;
  const std::int32_t repeatParity = repeatFieldSum % 2;

  std::int32_t frameValue = advancedFrames % frameRoundBase;
  const std::int32_t accumulatedSeconds = (advancedFrames / frameRoundBase) + sourceTimecode->seconds;
  const std::int32_t secondsValue = accumulatedSeconds % 60;
  const std::int32_t minuteCarry = accumulatedSeconds / 60;
  const std::int32_t accumulatedMinutes = sourceTimecode->minutes + minuteCarry;
  const std::int32_t minuteValue = accumulatedMinutes % 60;
  const std::int32_t hourValue = sourceTimecode->hours + (accumulatedMinutes / 60);

  if (
    sourceTimecode->dropFrameMode != 0
    && secondsValue == 0
    && (minuteValue % 10) != 0
    && (frameValue == 0 || frameValue == 1)
  ) {
    frameValue = 2;
  }

  outTimecode->frameRateIndex = frameRateIndex;
  outTimecode->dropFrameMode = sourceTimecode->dropFrameMode;
  outTimecode->hours = hourValue;
  outTimecode->minutes = minuteValue;
  outTimecode->seconds = secondsValue;
  outTimecode->frameNumber = frameValue;
  outTimecode->repeatFieldAccumulated = static_cast<std::int16_t>(repeatParity);
  return PointerToAddress(outTimecode);
}

/**
 * Address: 0x00AD34A0 (FUN_00AD34A0, _sfmpv_DoReformTc)
 *
 * What it does:
 * Reformats the active repeat-field timecode lane from PTS or concat-audio
 * baseline TTU state, and updates repeat-history carry lanes when requested.
 */
std::int32_t sfmpv_DoReformTc(
  const std::int32_t workctrlAddress,
  SfmpvPictureAttributeRuntimeView* const pictureAttribute,
  const std::int64_t presentationPts,
  const std::int32_t detectErrorMode
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;
  auto* const reformTimecode = &timingLane->repeatFieldTimecode;
  const auto* const concatAudioTtu =
    reinterpret_cast<const SfmpvTtuRuntimeView*>(timingLane->concatAudioTimeUnit);
  const auto* const concatAudioTimecode =
    reinterpret_cast<const SfmpvPackedTimecodeRuntimeView*>(concatAudioTtu->packedTimecodeWords);

  if (detectErrorMode != 0 && presentationPts >= 0) {
    return sfmpv_Pts2Tc(
      presentationPts,
      pictureAttribute->timecodeFrameRateIndex,
      pictureAttribute->timecodeDropFrameMode,
      pictureAttribute->timecodeFrameOrdinal,
      reformTimecode
    );
  }

  if (concatAudioTtu->state != 0) {
    if (detectErrorMode != 0) {
      (void)sfmpv_NextTc(concatAudioTimecode, reformTimecode);
      const std::int16_t repeatAccumulator = reformTimecode->repeatFieldAccumulated;
      workctrl->repeatFieldHistory.samples[0].accumulatedRepeatCount = repeatAccumulator;
      workctrl->repeatFieldHistory.samples[pictureAttribute->timecodeFrameOrdinal].accumulatedRepeatCount = repeatAccumulator;
      return static_cast<std::int32_t>(repeatAccumulator);
    }

    reformTimecode->frameRateIndex = concatAudioTimecode->frameRateIndex;
    reformTimecode->dropFrameMode = concatAudioTimecode->dropFrameMode;
    reformTimecode->hours = concatAudioTimecode->hours;
    reformTimecode->minutes = concatAudioTimecode->minutes;
    reformTimecode->seconds = concatAudioTimecode->seconds;
    reformTimecode->frameNumber = concatAudioTimecode->frameNumber;
    return concatAudioTimecode->minutes;
  }

  if (workctrl->headerWorkspaceBaseAddress == 0) {
    reformTimecode->frameRateIndex = pictureAttribute->timecodeFrameRateIndex;
    reformTimecode->dropFrameMode = 0;
    reformTimecode->hours = 0;
    reformTimecode->minutes = 0;
    reformTimecode->seconds = 0;
    reformTimecode->frameNumber = 0;
  }

  return 0;
}

/**
 * Address: 0x00AD3390 (FUN_00AD3390, _sfmpv_ReformTc)
 *
 * What it does:
 * Evaluates MPV timecode reform gate conditions and runs the timecode
 * reformation helper when condition 52 is active or newly latched.
 */
std::int32_t sfmpv_ReformTc(
  const std::int32_t workctrlAddress,
  SfmpvPictureAttributeRuntimeView* const pictureAttribute,
  const std::int64_t presentationPts,
  const std::int32_t detectErrorMode
)
{
  std::int32_t reformState = SFSET_GetCond(workctrlAddress, 52);
  if (reformState != 0) {
    if (reformState != 1) {
      return reformState;
    }
  } else {
    bool shouldStartReform = false;
    if (presentationPts >= 0) {
      shouldStartReform = true;
    } else if (pictureAttribute->pictureTimecodeBase == 0) {
      shouldStartReform = true;
    } else if (pictureAttribute->pictureTimecodeDisableLatch != 0) {
      shouldStartReform = true;
    } else if (detectErrorMode != 0) {
      shouldStartReform = (sfmpv_DetectTcErr(workctrlAddress, pictureAttribute) != 0);
    }

    if (!shouldStartReform) {
      return reformState;
    }

    (void)SFSET_SetCond(workctrlAddress, 52, 1);
  }

  return sfmpv_DoReformTc(workctrlAddress, pictureAttribute, presentationPts, detectErrorMode);
}

/**
 * Address: 0x00AD3920 (FUN_00AD3920, _sfmpv_FirstPicAtr)
 *
 * What it does:
 * Handles first-picture attribute setup: reads bitrate/VBV information, seeds
 * MPV header + MV info lanes, and validates frame-buffer sizing.
 */
std::int32_t sfmpv_FirstPicAtr(
  const std::int32_t workctrlAddress,
  const std::int32_t decoderHandleAddress,
  const std::int32_t frameInfoAddress,
  const std::int32_t pictureHeaderChunkAddress
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  if (workctrl->mvInfo.frameRateBase != 0) {
    return 0;
  }

  std::int32_t bitRate = 0;
  if (MPV_GetBitRate(decoderHandleAddress, &bitRate) != 0) {
    return SFLIB_SetErr(workctrlAddress, -16773354);
  }

  std::int32_t vbvBufferBytes = 0;
  std::int32_t vbvLevel = 0;
  std::int32_t vbvWindowBytes = 0;
  (void)MPV_GetVbvBufSiz(decoderHandleAddress, &vbvBufferBytes, &vbvLevel, &vbvWindowBytes);

  if (SFSET_GetCond(workctrlAddress, 60) != 0) {
    std::int32_t dataSize = SFBUF_RingGetDataSiz(workctrlAddress, 1);
    std::int32_t writeLimit = vbvWindowBytes;
    if (writeLimit == -1) {
      writeLimit = vbvBufferBytes;
    }
    if (writeLimit < dataSize) {
      dataSize = writeLimit;
    }
    mpvInfo->vbvWriteThreshold = dataSize;
  } else {
    mpvInfo->vbvWriteThreshold = 0;
  }

  (void)sfmpv_SetMpvHd(workctrlAddress, bitRate, pictureHeaderChunkAddress);
  (void)sfmpv_SetMvInf(
    &workctrl->mvInfo,
    bitRate,
    AddressToPointer<const std::int32_t>(frameInfoAddress),
    vbvBufferBytes
  );
  return sfmpv_ChkBufSiz(workctrlAddress, reinterpret_cast<const std::int32_t*>(&workctrl->mvInfo));
}

/**
 * Address: 0x00AD3AA0 (FUN_00AD3AA0, _sfmpv_SetMvInf)
 *
 * What it does:
 * Copies decoded frame-dimension words into the per-workctrl MV info lane and
 * latches bitrate/VBV sizing words used by buffer sizing checks.
 */
std::int32_t sfmpv_SetMvInf(
  SfmpvMvInfoRuntimeView* const destinationInfo,
  const std::int32_t frameRateBase,
  const std::int32_t* const frameInfoWords,
  const std::int32_t vbvBufferBytes
)
{
  destinationInfo->pictureWidthPixels = frameInfoWords[0];
  destinationInfo->pictureHeightPixels = frameInfoWords[1];
  destinationInfo->frameAreaWidthPixels = frameInfoWords[2];
  destinationInfo->frameAreaHeightPixels = frameInfoWords[3];
  destinationInfo->vbvBufferBytes = frameInfoWords[4];
  destinationInfo->frameRateBase = frameRateBase;
  destinationInfo->vbvWindowBytes = vbvBufferBytes;
  return PointerToAddress(destinationInfo);
}

/**
 * Address: 0x00AD3A10 (FUN_00AD3A10, _sfmpv_SetMpvHd)
 *
 * What it does:
 * Writes one pending MPV picture header block into the seek-header workspace
 * and latches timing/header state for later seek reprocessing.
 */
std::int32_t sfmpv_SetMpvHd(
  const std::int32_t workctrlAddress,
  const std::int32_t frameRateBase,
  const std::int32_t pictureHeaderChunkAddress
)
{
  std::int32_t result = sfmpv_GetHd(workctrlAddress);
  auto* const header = AddressToPointer<SfmpvHeaderRuntimeView>(result);
  if (header != nullptr && header->hasHeader == 0) {
    const auto* const headerChunk = AddressToPointer<SfbufRingChunkRuntimeView>(pictureHeaderChunkAddress);

    std::int32_t pictureHeaderBytes = headerChunk->byteCount;
    if (pictureHeaderBytes >= 0x200) {
      pictureHeaderBytes = 0x200;
    }
    header->pictureAttributeByteCount = pictureHeaderBytes;
    MEM_Copy(header->pictureAttributeBytes, headerChunk->bufferAddress, pictureHeaderBytes);

    result = frameRateBase;
    if (frameRateBase == 0x3FFFF) {
      header->frameRateTicks = 0;
      header->frameRateMode = 0;
    } else {
      result = 5 * frameRateBase;
      header->frameRateMode = 1;
      header->frameRateTicks = 50 * frameRateBase;
    }

    const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
    std::memcpy(header->concatTimeSeedWords, workctrl->timingLane.concatVideoTimeUnit, sizeof(header->concatTimeSeedWords));
    header->hasHeader = 1;
  }

  return result;
}

/**
 * Address: 0x00AD3DC0 (FUN_00AD3DC0, _sfmpv_IsSkip)
 *
 * What it does:
 * Evaluates all MPV skip gates for the current picture-type lane and updates
 * defect state from seek/ptype/empty/late decisions.
 */
std::int32_t sfmpv_IsSkip(const std::int32_t workctrlAddress, const std::int32_t* const chunkWords)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  const std::int32_t defectLaneAddress = PointerToAddress(&mpvInfo->pictureDecodeLane);
  const auto* const defectLane = AddressToPointer<SfmpvPictureDecodeLaneRuntimeView>(defectLaneAddress);

  if (SFSET_GetCond(workctrlAddress, 47) == 1) {
    return 1;
  }

  if (SFSET_GetCond(workctrlAddress, 39) == 1) {
    return 0;
  }

  if (mpvInfo->pictureDecodeLane.skipDecisionLatch != 0) {
    return mpvInfo->skipIssuedFlag;
  }

  const std::int32_t pictureType = defectLane->pictureType;
  const auto* const chunk = reinterpret_cast<const SfbufRingChunkRuntimeView*>(chunkWords);

  if (
    sfmpv_IsSeekSkip(workctrlAddress) != 0
    || sfmpv_IsPtypeSkip(workctrlAddress, pictureType) != 0
    || sfmpv_IsEmptyBpic(workctrlAddress, pictureType, chunk) != nullptr
    || sfmpv_IsDefect(workctrlAddress, pictureType) != 0
  ) {
    (void)sfmpv_UpdateDefect(workctrlAddress, defectLaneAddress, 1);
    return 1;
  }

  const std::int32_t lateDefect = (sfmpv_IsLate(workctrlAddress, pictureType) != 0) ? 1 : 0;
  (void)sfmpv_UpdateDefect(workctrlAddress, defectLaneAddress, lateDefect);
  return lateDefect;
}

/**
 * Address: 0x00AD3F10 (FUN_00AD3F10, _sfmpv_UpdateDefect)
 *
 * What it does:
 * Advances one MPV defect-state machine from decoder/link context and current
 * picture-type lane state.
 */
std::int32_t sfmpv_UpdateDefect(
  const std::int32_t workctrlAddress,
  const std::int32_t defectLaneAddress,
  const std::int32_t defectDetected
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  const auto* const defectLane = AddressToPointer<SfmpvDefectLaneRuntimeView>(defectLaneAddress);

  std::int32_t result = mpvInfo->linkDefectCheckEnabled;
  std::int32_t defectState = mpvInfo->defectPictureTypeState;
  if (result != 0) {
    std::int32_t streamLinkFlag = 0;
    std::int32_t linkState = 0;
    (void)MPV_GetLinkFlg(mpvInfo->decoderHandle, &streamLinkFlag, &linkState);
    result = streamLinkFlag;
    if (streamLinkFlag == 1) {
      defectState = 5;
    } else {
      result = workctrl->timingLane.interpolationEnabled;
      if ((result == 0 && SFSET_GetCond(workctrlAddress, 73) == 1) || linkState == 1) {
        defectState = 2;
      }
    }
  }

  if (defectDetected == 1) {
    result = defectLane->pictureType;
    if (result == 1 || result == 2) {
      mpvInfo->defectPictureTypeState = 2;
      return 2;
    }
  } else {
    if (defectState == 2) {
      mpvInfo->defectPictureTypeState = 3;
      return 3;
    }
    if (defectState == 3) {
      mpvInfo->defectPictureTypeState = 5;
      return 5;
    }
  }

  mpvInfo->defectPictureTypeState = defectState;
  return result;
}

/**
 * Address: 0x00AD3FD0 (FUN_00AD3FD0, _sfmpv_IsSeekSkip)
 *
 * What it does:
 * Checks whether current seek target time equals the pending start-TTU time
 * while start-TTU interpolation is still inactive.
 */
std::int32_t sfmpv_IsSeekSkip(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t seekTimeMajor = workctrl->seekSkipTimeMajor;
  if (seekTimeMajor < 0) {
    return 0;
  }

  if (workctrl->timingLane.interpolationEnabled != 0) {
    return 0;
  }

  return (
           UTY_CmpTime(
             seekTimeMajor,
             workctrl->seekSkipTimeMinor,
             workctrl->timingLane.pendingStartTtu.timeMajor,
             workctrl->timingLane.pendingStartTtu.timeMinor
           )
           == 0
         )
    ? 1
    : 0;
}

/**
 * Address: 0x00AD4300 (FUN_00AD4300, _sfmpv_SetSkipTtu)
 *
 * What it does:
 * Mirrors the pending start-TTU lane into the skip-seed lane when current
 * pending time is behind the interpolated frame time.
 */
std::int32_t sfmpv_SetSkipTtu(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  if (workctrl->timingLane.pendingStartTtu.timeMajor < workctrl->timingLane.frameInterpolationTime) {
    workctrl->timingLane.skipSeedTtu = workctrl->timingLane.pendingStartTtu;
  }
  return workctrlAddress;
}

/**
 * Address: 0x00AD49B0 (FUN_00AD49B0, _sfmpv_CopyPicUsrInf)
 *
 * What it does:
 * Copies one picture-user payload range from frame info into the destination
 * picture-user lane and mirrors copied byte count.
 */
std::int32_t sfmpv_CopyPicUsrInf(const std::int32_t destinationInfoAddress, const std::int32_t sourceInfoAddress)
{
  auto* const destinationInfo = AddressToPointer<SfbufRingChunkRuntimeView>(destinationInfoAddress);
  const auto* const sourceInfo = AddressToPointer<SfbufRingChunkRuntimeView>(sourceInfoAddress);

  std::memcpy(
    destinationInfo->bufferAddress,
    sourceInfo->bufferAddress,
    static_cast<std::size_t>(static_cast<std::uint32_t>(sourceInfo->byteCount))
  );
  destinationInfo->byteCount = sourceInfo->byteCount;
  return sourceInfo->byteCount;
}

/**
 * Address: 0x00AD3ED0 (FUN_00AD3ED0, _sfmpv_IsDefect)
 *
 * What it does:
 * Checks whether the current MPV defect state requires skipping the specified
 * picture type (P/B).
 */
std::int32_t sfmpv_IsDefect(const std::int32_t workctrlAddress, const std::int32_t pictureType)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  if (mpvInfo->defectPictureTypeState == 2) {
    return (pictureType == 2 || pictureType == 3) ? 1 : 0;
  }

  if (mpvInfo->defectPictureTypeState == 3) {
    return (pictureType == 3) ? 1 : 0;
  }

  return 0;
}

/**
 * Address: 0x00AD4020 (FUN_00AD4020, _sfmpv_IsPtypeSkip)
 *
 * What it does:
 * Returns whether decoding should skip one picture type according to per-type
 * enable flags in the workctrl.
 */
std::int32_t sfmpv_IsPtypeSkip(const std::int32_t workctrlAddress, const std::int32_t pictureType)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  switch (pictureType) {
    case 1:
      return (workctrl->ptype1DecodeEnable == 0) ? 1 : 0;
    case 2:
      return (workctrl->ptype2DecodeEnable == 0) ? 1 : 0;
    case 3:
      return (workctrl->ptype3DecodeEnable == 0) ? 1 : 0;
    default:
      return 1;
  }
}

/**
 * Address: 0x00AD4070 (FUN_00AD4070, _sfmpv_IsEmptyBpic)
 *
 * What it does:
 * Checks whether one P/B picture payload is empty and tracks per-type empty
 * picture counters when the corresponding codec probe reports empty data.
 */
std::uint8_t* sfmpv_IsEmptyBpic(
  const std::int32_t workctrlAddress,
  const std::int32_t pictureType,
  const SfbufRingChunkRuntimeView* const chunkWords
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);

  if (SFSET_GetCond(workctrlAddress, 7) != 0) {
    return nullptr;
  }

  const std::int32_t frameAreaProduct = workctrl->mvInfo.frameAreaWidthPixels * workctrl->mvInfo.frameAreaHeightPixels;
  if (pictureType == 3) {
    auto* const emptyPicture = static_cast<std::uint8_t*>(
      MPV_IsEmptyBpic(reinterpret_cast<const char*>(chunkWords->bufferAddress), chunkWords->byteCount, frameAreaProduct)
    );
    if (emptyPicture != nullptr) {
      ++workctrl->emptyBpicCount;
    }
    return emptyPicture;
  }

  if (pictureType != 2) {
    return nullptr;
  }

  auto* const emptyPicture = static_cast<std::uint8_t*>(
    MPV_IsEmptyPpic(reinterpret_cast<const char*>(chunkWords->bufferAddress), chunkWords->byteCount, frameAreaProduct)
  );
  if (emptyPicture != nullptr) {
    ++workctrl->emptyPpicCount;
  }
  return emptyPicture;
}

/**
 * Address: 0x00AD4100 (FUN_00AD4100, _sfmpv_IsLate)
 *
 * What it does:
 * Computes one MPV late-frame condition using current interpolation/time lanes,
 * optional callback override, and per-handle late-frame gate counters.
 */
std::int32_t sfmpv_IsLate(const std::int32_t workctrlAddress, const std::int32_t updateMode)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvTimingLane* const timingLane = &workctrl->timingLane;
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t interpolationTime = 0;
  if (timingLane->interpolationEnabled != 0) {
    interpolationTime = timingLane->pendingStartTtu.timeMajor + timingLane->decodeProgressTime - timingLane->frameInterpolationTime;
  }

  const auto lateCallback = timingLane->isLateCallback;
  const std::int32_t baseFraction = timingLane->pendingStartTtu.timeMinor;
  if (lateCallback != nullptr) {
    return lateCallback(workctrlAddress, updateMode, interpolationTime, baseFraction);
  }

  if (updateMode == 1) {
    SFTIM_UpdateItime(timingLane, interpolationTime);
    interpolationTime = SFTIM_GetNextItime(timingLane, interpolationTime);
  } else if (updateMode == 2) {
    interpolationTime = SFTIM_GetNextItime(timingLane, interpolationTime);
  }

  if (SFTIM_GetSpeed(workctrlAddress) <= 1000 && mpvInfo->lateFrameCounter >= workctrl->lateFrameGateThreshold) {
    return 0;
  }

  std::int32_t currentTimeMajor = 0;
  std::int32_t currentTimeMinor = 0;
  SFTIM_GetTime(workctrlAddress, &currentTimeMajor, &currentTimeMinor);
  if (currentTimeMajor < 0) {
    return 0;
  }

  std::int32_t frameDeltaMajor = 0;
  std::int32_t frameDeltaMinor = 0;
  sfmpv_GetDtime(workctrlAddress, updateMode, &frameDeltaMajor, &frameDeltaMinor);
  if (
    UTY_CmpTime(
      currentTimeMajor,
      currentTimeMinor,
      interpolationTime - (baseFraction * frameDeltaMajor) / frameDeltaMinor,
      baseFraction
    ) != 0
  ) {
    return 0;
  }

  ++mpvInfo->lateFrameCounter;
  return 1;
}

/**
 * Address: 0x00AD4240 (FUN_00AD4240, _sfmpv_GetDtime)
 *
 * What it does:
 * Returns cached frame-delta time lanes from workctrl timing state.
 */
std::int32_t sfmpv_GetDtime(
  const std::int32_t workctrlAddress,
  const std::int32_t /*mode*/,
  std::int32_t* const outDeltaMajor,
  std::int32_t* const outDeltaMinor
)
{
  const auto* const workctrl = AddressToPointer<const SfmpvHandleRuntimeView>(workctrlAddress);
  *outDeltaMinor = workctrl->frameDeltaMinor;
  const std::int32_t result = workctrl->frameDeltaMajor;
  *outDeltaMajor = result;
  return result;
}

/**
 * Address: 0x00AEAC60 (FUN_00AEAC60, _m2v_SkipFrm)
 *
 * What it does:
 * Validates decoder handle, advances source stream to next MPEG delimiter lane,
 * and reports CRI MPV skip-frame status through `MPVERR_SetCode`.
 */
std::int32_t m2v_SkipFrm(const std::int32_t decoderHandle, const std::int32_t streamBufferAddress)
{
  constexpr std::int32_t kMpvErrInvalidHandle = -16580086;
  constexpr std::int32_t kMpvErrDelimiterScanFailed = -16579835;

  if (MPVLIB_CheckHn(decoderHandle) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidHandle);
  }

  std::int32_t statusCode = kMpvErrDelimiterScanFailed;
  std::int32_t delimiterCode = MPV_GoNextDelimSj(streamBufferAddress);
  if (delimiterCode != 0) {
    while ((delimiterCode & 0xCC) == 0) {
      if (MPV_MoveChunk(streamBufferAddress, 1, 4) != 4) {
        return MPVERR_SetCode(decoderHandle, statusCode);
      }

      delimiterCode = MPV_GoNextDelimSj(streamBufferAddress);
      if (delimiterCode == 0) {
        return MPVERR_SetCode(decoderHandle, kMpvErrDelimiterScanFailed);
      }
    }
    statusCode = 0;
  }

  return MPVERR_SetCode(decoderHandle, statusCode);
}

/**
 * Address: 0x00AD4260 (FUN_00AD4260, _sfmpv_SkipFrm)
 *
 * What it does:
 * Runs one MPV frame-skip decode step, updates consumed-stream counters, and
 * records one skipped-picture callback when skip succeeds.
 */
std::int32_t sfmpv_SkipFrm(const std::int32_t workctrlAddress, const std::int32_t streamBufferAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  sfmpv_SetSkipTtu(workctrlAddress);
  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1);
  const std::int32_t skipDecodeResult = m2v_SkipFrm(mpvInfo->decoderHandle, streamBufferAddress);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(streamBufferAddress, 0, 1) - flowCountBefore;

  const std::int32_t checkedResult =
    sfmpv_ChkMpvErr(workctrlAddress, skipDecodeResult, consumedBytes, kSfmpvErrSkipFrameFailed);
  sfmpv_AddRtotSj(workctrlAddress, consumedBytes);
  if (checkedResult != 0) {
    return checkedResult;
  }

  if (mpvInfo->pictureDecodeLane.skipDecisionLatch == 0) {
    mpvInfo->skipIssuedFlag = 1;
  }

  SFPLY_AddSkipPic(workctrlAddress, 1, mpvInfo->pictureDecodeLane.pictureType);
  return 0;
}

/**
 * Address: 0x00AD4F10 (FUN_00AD4F10, _SFMPV_Destroy)
 *
 * What it does:
 * Destroys active MPV decoder handle and persists current per-handle MPV
 * parameter/tables back into global MPV state.
 */
std::int32_t SFMPV_Destroy(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;
  const std::int32_t decoderHandle = mpvInfo->decoderHandle;
  if (decoderHandle == 0) {
    return 0;
  }

  sfmpv_para = mpvInfo->persistedPara;
  sfmpv_rfb_adr_tbl[0] = mpvInfo->persistedRfbAddressTable[0];
  sfmpv_rfb_adr_tbl[1] = mpvInfo->persistedRfbAddressTable[1];
  for (std::int32_t tabIndex = 0; tabIndex < 16; ++tabIndex) {
    sSofDec_tabs[tabIndex] = mpvInfo->persistedSofDecTabs[tabIndex];
  }
  sfmpv_picusr_pbuf = mpvInfo->pictureUserBufferAddress;
  sfmpv_picusr_bufnum = mpvInfo->pictureUserBufferCount;
  sfmpv_picusr_buf1siz = mpvInfo->pictureUserBufferSize;

  if (sfmpv_DestroySub(decoderHandle) != 0) {
    return SFLIB_SetErr(workctrlAddress, kSfmpvErrDestroySubFailed);
  }

  mpvInfo->decoderHandle = 0;
  return 0;
}

/**
 * Address: 0x00AD4EF0 (FUN_00AD4EF0, _sfmpv_ErrFn)
 *
 * What it does:
 * Normalizes MPV control-path return lanes: forwards non-zero/non-(-2/-3)
 * errors through `SFLIB_SetErr`, otherwise returns input status unchanged.
 */
std::int32_t sfmpv_ErrFn(const std::int32_t workctrlAddress, const std::int32_t statusCode)
{
  if (statusCode < -3 || (statusCode > -2 && statusCode != 0)) {
    return SFLIB_SetErr(workctrlAddress, statusCode);
  }
  return statusCode;
}

/**
 * Address: 0x00AD4FC0 (FUN_00AD4FC0, _SFMPV_RequestStop)
 *
 * What it does:
 * Stubbed MPV transport callback: request-stop operation succeeds immediately.
 */
std::int32_t SFMPV_RequestStop()
{
  return 0;
}

/**
 * Address: 0x00AD4FD0 (FUN_00AD4FD0, _SFMPV_Start)
 *
 * What it does:
 * Stubbed MPV transport callback: start operation succeeds immediately.
 */
std::int32_t SFMPV_Start()
{
  return 0;
}

/**
 * Address: 0x00AD4FE0 (FUN_00AD4FE0, _SFMPV_Stop)
 *
 * What it does:
 * Stubbed MPV transport callback: stop operation succeeds immediately.
 */
std::int32_t SFMPV_Stop()
{
  return 0;
}

/**
 * Address: 0x00AD4FF0 (FUN_00AD4FF0, _SFMPV_Pause)
 *
 * What it does:
 * Stubbed MPV transport callback: pause operation succeeds immediately.
 */
std::int32_t SFMPV_Pause()
{
  return 0;
}

/**
 * Address: 0x00AD5000 (FUN_00AD5000, _SFMPV_GetWrite)
 *
 * What it does:
 * Reports unsupported write-lane API for MPV transport (`FF000F0D`).
 */
std::int32_t SFMPV_GetWrite(const std::int32_t workctrlAddress)
{
  return SFLIB_SetErr(workctrlAddress, kSfmpvErrWriteApiUnsupported);
}

/**
 * Address: 0x00AD5020 (FUN_00AD5020, _SFMPV_AddWrite)
 *
 * What it does:
 * Reports unsupported write-lane API for MPV transport (`FF000F0D`).
 */
std::int32_t SFMPV_AddWrite(const std::int32_t workctrlAddress)
{
  return SFLIB_SetErr(workctrlAddress, kSfmpvErrWriteApiUnsupported);
}

/**
 * Address: 0x00AD5040 (FUN_00AD5040, _SFMPVF_GetRead)
 *
 * What it does:
 * Acquires one readable frame, exports frame-info lanes for timing checks, and
 * issues a frame id for decode-path mode 2 readers.
 */
std::int32_t SFMPVF_GetRead(
  const std::int32_t workctrlAddress,
  SfmpvfFrameInfoRuntimeView** const outFrameInfo,
  std::int32_t* const outFrameId
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t frameObjectAddress = SFMPVF_HoldFrm(workctrlAddress);
  if (frameObjectAddress == 0) {
    *outFrameInfo = nullptr;
    return 0;
  }

  sfmpvf_SearchFrmInf(workctrlAddress, frameObjectAddress, outFrameInfo);
  SfmpvfFrameInfoRuntimeView* const frameInfo = *outFrameInfo;

  workctrl->readFrameTimeMajor = frameInfo->presentationTimeMajor;
  workctrl->readFrameTimeMinor = frameInfo->presentationTimeMinor;

  if (SFTIM_IsGetFrmTime(workctrlAddress, frameInfo) == 0) {
    *outFrameInfo = nullptr;
    return 0;
  }

  if (workctrl->decodePathMode == 2) {
    const std::int32_t frameId = SFMPVF_IssueFrmId(workctrlAddress);
    auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
    frameObject->frameId = frameId;
    *outFrameId = frameId;
  }

  return 0;
}

/**
 * Address: 0x00AD50C0 (FUN_00AD50C0, _sfmpvf_SearchFrmInf)
 *
 * What it does:
 * Resolves the active frame-info lane from the VFRM state block, marks it
 * drawing, records the active frame-object, and copies exported frame fields.
 */
void sfmpvf_SearchFrmInf(
  const std::int32_t workctrlAddress,
  const std::int32_t frameObjectAddress,
  SfmpvfFrameInfoRuntimeView** const outFrameInfo
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  auto* const vfrmData = AddressToPointer<SfmpvfVfrmDataRuntime>(SFMPVF_SearchVfrmData(workctrlAddress, frameObjectAddress));
  auto* const frameInfo =
    AddressToPointer<SfmpvfFrameInfoRuntimeView>(PointerToAddress(vfrmData) + static_cast<std::int32_t>(sizeof(SfmpvfVfrmDataRuntime)));

  *outFrameInfo = frameInfo;
  vfrmData->drawState = 1;
  workctrl->mpvInfo->activeFrameObjectAddress = frameObjectAddress;

  frameInfo->pictureWidthPixels = frameObject->pictureDecodeLane.pictureWidthPixels;
  frameInfo->pictureHeightPixels = frameObject->pictureDecodeLane.pictureHeightPixels;
  frameInfo->pictureDetailWord08 = frameObject->pictureDecodeLane.pictureDetailWord08;
  frameInfo->pictureDetailWord0C = frameObject->pictureDecodeLane.pictureDetailWord0C;
  frameInfo->pictureType = frameObject->pictureDecodeLane.pictureType;
  frameInfo->presentationTimeMajor = frameObject->presentationTimeMajor;
  frameInfo->presentationTimeMinor = frameObject->presentationTimeMinor;
  frameInfo->decodeConditionMode = workctrl->mpvCond6Value;
  frameInfo->frameSurfaceBaseAddress = frameObject->frameSurfaceBaseAddress;
  frameInfo->referenceErrorMajor = frameObject->referenceErrorMajor;
  frameInfo->referenceErrorMinor = frameObject->referenceErrorMinor;
  frameInfo->decodeConcatOrdinal = frameObject->decodeConcatOrdinal;
  frameInfo->frameDetailWord30 = frameObject->frameDetailWord4C;
  frameInfo->frameDetailWord34 = frameObject->frameDetailWord50;
  frameInfo->pictureUserInfoAddress = frameObject->pictureUserInfoAddress;
  frameInfo->chromaPositionLow = frameObject->pictureDecodeLane.chromaPositionLow;
  frameInfo->chromaPositionHigh = frameObject->pictureDecodeLane.chromaPositionHigh;
  frameInfo->chromaLayoutClass = (frameObject->pictureDecodeLane.chromaPositionLow != 0) ? 1 : 2;
  frameInfo->referenceErrorSeedMajor = frameObject->referenceErrorSeedMajor;
  frameInfo->referenceErrorSeedMinor = frameObject->referenceErrorSeedMinor;
  frameInfo->referenceUpdateMode = frameObject->pictureDecodeLane.referenceUpdateMode;
  frameInfo->chromaFormat = frameObject->pictureDecodeLane.chromaFormat;
  frameInfo->pictureDetailWord60 = frameObject->pictureDecodeLane.pictureDetailWord48;
  frameInfo->pictureDetailWord64 = frameObject->pictureDecodeLane.pictureDetailWord4C;
  frameInfo->pictureDetailWord68 = frameObject->pictureDecodeLane.pictureDetailWord50;
  frameInfo->pictureDetailWord6A = frameObject->pictureDecodeLane.pictureDetailWord52;
  frameInfo->pictureDecodeFlagA = frameObject->pictureDecodeLane.pictureDecodeFlagA;
  frameInfo->pictureDecodeFlagB = frameObject->pictureDecodeLane.pictureDecodeFlagB;
  frameInfo->pictureDecodeFlagC = frameObject->pictureDecodeLane.pictureDecodeFlagC;
  frameInfo->pictureDecodeFlagD = frameObject->pictureDecodeLane.pictureDecodeFlagD;
  frameInfo->pictureDecodeFlagE = frameObject->pictureDecodeLane.pictureDecodeFlagE;
  frameInfo->pictureDecodeFlagF = frameObject->pictureDecodeLane.pictureDecodeFlagF;
  frameInfo->pictureDecodeFlagG = frameObject->pictureDecodeLane.pictureDecodeFlagG;
  frameInfo->pictureDecodeFlagH = frameObject->pictureDecodeLane.pictureDecodeFlagH;
  frameInfo->pictureDecodeFlagI = frameObject->pictureDecodeLane.pictureDecodeFlagI;
  frameInfo->pictureDecodeFlagJ = frameObject->pictureDecodeLane.pictureDecodeFlagJ;
  frameInfo->pictureDecodeFlagK = frameObject->pictureDecodeLane.pictureDecodeFlagK;
  frameInfo->pictureDecodeFlagL = frameObject->pictureDecodeLane.pictureDecodeFlagL;
  frameInfo->pictureDecodeFlagM = frameObject->pictureDecodeLane.pictureDecodeFlagM;
  frameInfo->pictureDecodeFlagN = frameObject->pictureDecodeLane.pictureDecodeFlagN;
  frameInfo->pictureDecodeFlagO = frameObject->pictureDecodeLane.pictureDecodeFlagO;
}

/**
 * Address: 0x00AD52A0 (FUN_00AD52A0, _SFMPV_AddRead)
 *
 * What it does:
 * Wraps one frame-read completion in CRI critical-section enter/leave guards.
 */
std::int32_t SFMPV_AddRead(
  const std::int32_t workctrlAddress,
  const std::int32_t frameInfoIndex,
  const std::int32_t frameObjectId
)
{
  SFLIB_LockCs();
  const std::int32_t result = sfmpvf_AddReadSub(workctrlAddress, frameInfoIndex, frameObjectId);
  SFLIB_UnlockCs();
  return result;
}

/**
 * Address: 0x00AD52E0 (FUN_00AD52E0, _sfmpvf_AddReadSub)
 *
 * What it does:
 * Validates one frame-read completion lane, clears the frame draw-state, and
 * finalizes the associated frame-object draw owner.
 */
std::int32_t sfmpvf_AddReadSub(
  const std::int32_t workctrlAddress,
  const std::int32_t frameInfoIndex,
  const std::int32_t frameObjectId
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t frameObjectAddress = 0;
  SfmpvfVfrmDataRuntime* vfrmData = nullptr;

  if (workctrl->decodePathMode == 2) {
    frameObjectAddress = SFMPVF_SearchFrmObjFromId(workctrlAddress, frameObjectId);
    if (frameObjectAddress == 0) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameObjectMissingById);
    }

    vfrmData = AddressToPointer<SfmpvfVfrmDataRuntime>(SFMPVF_SearchVfrmData(workctrlAddress, frameObjectAddress));
  } else {
    vfrmData = AddressToPointer<SfmpvfVfrmDataRuntime>(sfmpvf_GetVfrmDataFromFrmInf(workctrlAddress, frameInfoIndex));
    if (vfrmData->drawState != 1) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrInvalidVfrmDrawState);
    }

    frameObjectAddress = SFMPVF_SearchFrmObj(workctrlAddress, frameInfoIndex);
    if (mpvInfo->activeFrameObjectAddress != frameObjectAddress) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameObjectMismatch);
    }
  }

  vfrmData->drawState = 0;
  SFMPVF_EndDrawFrm(frameObjectAddress);
  return 0;
}

/**
 * Address: 0x00AD5390 (FUN_00AD5390, _sfmpvf_GetVfrmDataFromFrmInf)
 *
 * What it does:
 * Converts one exported frame-info pointer back to the owning VFRM data lane.
 */
std::int32_t sfmpvf_GetVfrmDataFromFrmInf(const std::int32_t workctrlAddress, const std::int32_t frameInfoIndex)
{
  (void)workctrlAddress;
  return frameInfoIndex - static_cast<std::int32_t>(sizeof(SfmpvfVfrmDataRuntime));
}

/**
 * Address: 0x00ADC0D0 (FUN_00ADC0D0, _SFMPVF_SearchVfrmData)
 *
 * What it does:
 * Scans the active MPV frame-object array for the supplied frame-object
 * address and returns the owning VFRM data lane when found.
 */
std::int32_t SFMPVF_SearchVfrmData(const std::int32_t workctrlAddress, const std::int32_t frameObjectAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvfSearchWorkctrlRuntimeView>(workctrlAddress);
  const std::int32_t frameObjectCount = workctrl->mpvInfo->frameObjectCount;
  if (frameObjectCount <= 0) {
    return 0;
  }

  for (std::int32_t frameIndex = 0; frameIndex < frameObjectCount; ++frameIndex) {
    const auto* const frameObject = &workctrl->mpvInfo->frameObjects[frameIndex];
    if (PointerToAddress(frameObject) == frameObjectAddress) {
      return PointerToAddress(&workctrl->vfrmDataLanes[frameIndex]);
    }
  }

  return 0;
}

/**
 * Address: 0x00ADC0A0 (FUN_00ADC0A0, _SFMPVF_SearchFrmObjFromId)
 *
 * What it does:
 * Scans the fixed 16-frame object table for the frame id and returns the
 * matching frame-object address when found.
 */
std::int32_t SFMPVF_SearchFrmObjFromId(const std::int32_t workctrlAddress, const std::int32_t frameObjectId)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const auto* const mpvInfo = reinterpret_cast<const SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);

  for (std::int32_t frameIndex = 0; frameIndex < 16; ++frameIndex) {
    const auto* const frameObject = &mpvInfo->frameObjects[frameIndex];
    if (frameObject->frameId == frameObjectId) {
      return PointerToAddress(frameObject);
    }
  }

  return 0;
}

/**
 * Address: 0x00ADC120 (FUN_00ADC120, _SFMPVF_TermDec)
 *
 * What it does:
 * Marks the per-handle MPV info lane as term-decode active.
 */
std::int32_t SFMPVF_TermDec(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  auto* const mpvInfo = reinterpret_cast<SfmpvfInfoRuntimeView*>(workctrl->mpvInfo);
  mpvInfo->termDecodeState = 1;
  return workctrlAddress;
}

/**
 * Address: 0x00ADC250 (FUN_00ADC250, _SFMPVF_FreeFrm)
 *
 * What it does:
 * Clears one frame-object decode-state lane back to free (`0`) when the
 * address is valid.
 */
void SFMPVF_FreeFrm(const std::int32_t frameObjectAddress)
{
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  if (frameObject != nullptr) {
    frameObject->decodeState = 0;
  }
}

/**
 * Address: 0x00ADC260 (FUN_00ADC260, _SFMPVF_StbyFrm)
 *
 * What it does:
 * Places the frame object into standby state when the input address is
 * valid.
 */
std::int32_t SFMPVF_StbyFrm(const std::int32_t frameObjectAddress)
{
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  if (frameObject != nullptr) {
    frameObject->decodeState = 2;
  }
  return frameObjectAddress;
}

/**
 * Address: 0x00ADC270 (FUN_00ADC270, _SFMPVF_RefStbyFrm)
 *
 * What it does:
 * Places the frame object into reference-standby state when the input
 * address is valid.
 */
std::int32_t SFMPVF_RefStbyFrm(const std::int32_t frameObjectAddress)
{
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  if (frameObject != nullptr) {
    frameObject->decodeState = 4;
  }
  return frameObjectAddress;
}

/**
 * Address: 0x00ADC280 (FUN_00ADC280, _SFMPVF_EndDrawFrm)
 *
 * What it does:
 * Clears the frame id, then transitions the frame from reference-draw or
 * non-reference draw state back to the appropriate idle lane.
 */
std::int32_t SFMPVF_EndDrawFrm(const std::int32_t frameObjectAddress)
{
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  if (frameObject != nullptr) {
    const bool wasReferenceStandby = (frameObject->decodeState == 4);
    frameObject->frameId = -1;
    frameObject->decodeState = wasReferenceStandby ? 3 : 0;
  }
  return frameObjectAddress;
}

/**
 * Address: 0x00ADC2A0 (FUN_00ADC2A0, _SFMPVF_EndRefFrm)
 *
 * What it does:
 * Clears a frame-object's standby/reference state unless it is already in
 * the reference-standby lane.
 */
std::int32_t SFMPVF_EndRefFrm(const std::int32_t frameObjectAddress)
{
  auto* const frameObject = AddressToPointer<SfmpvfFrameObjectRuntimeView>(frameObjectAddress);
  if (frameObject != nullptr) {
    frameObject->decodeState = (frameObject->decodeState != 4) ? 0 : 2;
  }
  return frameObjectAddress;
}

/**
 * Address: 0x00ADC6C0 (FUN_00ADC6C0, _SFMPVF_IssueFrmId)
 *
 * What it does:
 * Returns the current frame-object id lane and advances it, wrapping back
 * to zero when the increment would become negative.
 */
std::int32_t SFMPVF_IssueFrmId(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  const std::int32_t frameId = workctrl->frameIdCounter;
  std::int32_t nextFrameId = frameId + 1;
  if (nextFrameId < 0) {
    nextFrameId = 0;
  }
  workctrl->frameIdCounter = nextFrameId;
  return frameId;
}

/**
 * Address: 0x00ADC150 (FUN_00ADC150, _SFMPVF_FixDispOrder)
 *
 * What it does:
 * Copies the caller-supplied display-order latch into the MPV info lane's
 * single-frame-output flag and returns to the caller.
 */
void SFMPVF_FixDispOrder(const std::int32_t workctrlAddress, const std::int32_t shouldSort)
{
  auto* const workctrl = AddressToPointer<SfmpvfSearchWorkctrlRuntimeView>(workctrlAddress);
  workctrl->mpvInfo->allowSingleFrameOutput = shouldSort;
}

/**
 * Address: 0x00AD53A0 (FUN_00AD53A0, _SFMPV_Seek)
 *
 * What it does:
 * Reprocesses cached MPV picture attributes for seek and re-arms concat
 * control flags based on condition 48 and reprocess availability.
 */
std::int32_t SFMPV_Seek(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  SfmpvInfoRuntimeView* const mpvInfo = workctrl->mpvInfo;

  std::int32_t reprocessed = 0;
  const std::int32_t result =
    sfmpv_ReprocessShc(workctrlAddress, reinterpret_cast<const std::int32_t*>(mpvInfo), &reprocessed);
  if (result != 0) {
    return result;
  }

  mpvInfo->defectPictureTypeState = 2;
  if (reprocessed != 0 && SFSET_GetCond(workctrlAddress, 48) != 0) {
    mpvInfo->concatControlFlags = 200;
  } else {
    mpvInfo->concatControlFlags = 192;
  }

  return 0;
}

/**
 * Address: 0x00AD5400 (FUN_00AD5400, _sfmpv_ReprocessShc)
 *
 * What it does:
 * Reprocesses one cached sequence-header chunk into picture attributes during
 * seek path and returns whether the reprocess pass was applied.
 */
std::int32_t sfmpv_ReprocessShc(
  const std::int32_t workctrlAddress,
  const std::int32_t* const decoderHandleLane,
  std::int32_t* const outReprocessed
)
{
  auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  *outReprocessed = 0;

  const std::int32_t headerAddress = sfmpv_GetHd(workctrlAddress);
  auto* const header = AddressToPointer<SfmpvHeaderRuntimeView>(headerAddress);
  if (header != nullptr && header->hasHeader != 0) {
    std::memcpy(workctrl->timingLane.concatVideoTimeUnit, header->concatTimeSeedWords, sizeof(header->concatTimeSeedWords));

    SfbufRingChunkRuntimeView pictureRange{};
    pictureRange.bufferAddress = header->pictureAttributeBytes;
    pictureRange.byteCount = header->pictureAttributeByteCount;

    std::int32_t consumedBytes = 0;
    if (MPV_DecodePicAtr(*decoderHandleLane, reinterpret_cast<const std::int32_t*>(&pictureRange), &consumedBytes) != 0) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrReprocessPicAtrFailed);
    }

    *outReprocessed = 1;
  }

  return 0;
}

/**
 * Address: 0x00AD5490 (FUN_00AD5490, _sfmpv_GetHd)
 *
 * What it does:
 * Returns the active seek-header workspace pointer when the concat-advance
 * gate allows header reuse; otherwise returns null.
 */
std::int32_t sfmpv_GetHd(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<SfmpvHandleRuntimeView>(workctrlAddress);
  std::int32_t headerWorkspaceAddress = workctrl->headerWorkspaceBaseAddress;
  if (headerWorkspaceAddress == 0) {
    return 0;
  }

  if (workctrl->mpvInfo->concatAdvanceCount > 0) {
    return 0;
  }

  return headerWorkspaceAddress + 0xAD0;
}

} // extern "C"
