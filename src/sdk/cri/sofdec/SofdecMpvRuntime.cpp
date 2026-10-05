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

#include "moho/audio/SofdecRuntime.h"

using moho::SfmpvPara;
using moho::SfmpvComplementPts;
using moho::SfmpvPicUsr;

struct SfmpvPictureAttribute;
struct SfmpvDecodeFrameParam;
struct SfbufRingChunk;
struct Mpvcmc;

// ---------------------------------------------------------------------------
// Forward declarations for CRI library functions used by this module
// ---------------------------------------------------------------------------

extern "C" {
  std::int32_t SFLIB_SetErr(std::int32_t errorObjectAddress, std::int32_t errorCode);
  std::int32_t sfmpv_ChkFatal();
  std::int32_t MPVLIB_CheckHn(std::int32_t decoderHandle);
  std::int32_t MPV_GoNextDelimSj(std::int32_t streamBufferAddress);
  std::int32_t MPV_MoveChunk(std::int32_t streamBufferAddress, std::int32_t laneIndex, std::int32_t byteCount);
  std::int32_t MPV_Finish();
  std::int32_t MPVERR_SetCode(std::int32_t decoderHandle, std::int32_t errorCode);
  std::int32_t SFMPVF_IsTermDec(std::int32_t workctrlAddress);
  std::int32_t SFMPVF_GetNumFrm(std::int32_t workctrlAddress);
  std::int32_t MPV_Init(std::int32_t framePoolCount, std::int32_t workAddress);
  std::int32_t MPV_Create();
  std::int32_t MPV_SetErrFunc(std::int32_t handleAddress, std::int32_t errorCallbackAddress, std::int32_t errorCallbackContext);
  std::int32_t MPV_SetCond(std::int32_t handleAddress, std::int32_t conditionId, std::int32_t (*conditionCallback)());
  std::int32_t M2V_Init(std::int32_t framePoolCount, void* workAddress, std::int32_t workBytes);
  std::int32_t UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
  std::int32_t UTY_MulDiv(std::int32_t lhs, std::int32_t rhs, std::int32_t divisor);
  std::int32_t SFTIM_InitTtu(std::uint32_t* timerState, std::int32_t initialValue);
  void SFTIM_UpdateItime(void* timerState, std::int32_t interpolationTime);
  std::int32_t SFTIM_GetNextItime(void* timerState, std::int32_t interpolationTime);
  std::int32_t SFTIM_IsGetFrmTime(std::int32_t workctrlAddress, const SfmpvfFrameInfo* frameInfo);
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
    moho::SfptsPtsQueue* ptsQueue,
    std::int32_t normalizedDelimiterAddress,
    std::int32_t* outPtsWords,
    std::int32_t sourceLaneStartAddress,
    std::int32_t sourceLaneSpanBytes
  );
  std::int32_t sfpts_SearchPtsQue(
    const moho::SfptsPtsQueue* ptsQueue,
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
  std::int32_t sfmpv_DetectTcErr(std::int32_t workctrlAddress, const SfmpvPictureAttribute* pictureAttribute);
  std::int32_t sfmpv_DoReformTc(
    std::int32_t workctrlAddress,
    SfmpvPictureAttribute* pictureAttribute,
    std::int64_t presentationPts,
    std::int32_t detectErrorMode
  );
  std::int32_t sfmpv_Pts2Tc(
    std::int64_t presentationPts,
    std::int32_t frameRateIndex,
    std::int32_t dropFrameMode,
    std::int32_t decodeOrderMetric,
    moho::SfmpvPackedTimecode* outTimecode
  );
  std::int32_t sfmpv_NextTc(
    const moho::SfmpvPackedTimecode* sourceTimecode,
    moho::SfmpvPackedTimecode* outTimecode
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
  sfmpv_IsEmptyBpic(std::int32_t workctrlAddress, std::int32_t pictureType, const SfbufRingChunk* chunkWords);
  std::int32_t sfmpv_CopyPicUsrInf(std::int32_t destinationInfoAddress, std::int32_t sourceInfoAddress);
  std::int32_t sfmpv_SetMpvHd(std::int32_t workctrlAddress, std::int32_t frameRateBase, std::int32_t pictureHeaderChunkAddress);
  std::int32_t sfmpv_SetStartTtu(std::int32_t workctrlAddress);
  std::int32_t sfmpv_ChkMpvErr(
    std::int32_t workctrlAddress,
    std::int32_t decodeResult,
    std::int32_t consumedBytes,
    std::int32_t errorCode
  );
  std::int32_t sfmpv_GetTermDst(std::int32_t workctrlAddress);
  std::int32_t sfmpv_GetTermSrc(std::int32_t workctrlAddress);
  std::int32_t sfmpv_ChkPrepFlg(std::int32_t workctrlAddress);
  std::int32_t sfmpv_ChkTermFlg(std::int32_t workctrlAddress);
  std::int32_t sfmpv_IsPrepEnd(std::int32_t workctrlAddress);
  std::int32_t sfmpv_IsPrepFrmEnough(std::int32_t workctrlAddress);
  std::int32_t sfmpv_IsVbvEnough(std::int32_t workctrlAddress);
  std::int32_t MPV_GetBitRate(std::int32_t decoderHandle, std::int32_t* outBitRate);
  std::int32_t MPV_GetVbvBufSiz(
    std::int32_t decoderHandle,
    std::int32_t* outBufferBytes,
    std::int32_t* outVbvLevel,
    std::int32_t* outStreamScale
  );
  std::int32_t sfmpv_DestroySub(std::int32_t decoderHandle);
  std::int32_t*
  SFBUF_AddRtotSj(std::int32_t sfbufHandleAddress, std::int32_t ringIndex, std::int32_t addBytes);
  std::int32_t sfmpv_AddRtotSj(std::int32_t workctrlAddress, std::int32_t consumedBytes);
  std::int32_t SFMPVF_HoldFrm(std::int32_t workctrlAddress);
  std::int32_t
  sfmpvf_IsChkFirst(const moho::SfmpvfFrameObject* selectedFrameObject, const moho::SfmpvfFrameObject* candidateFrameObject);
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
    SfmpvfFrameInfo** outFrameInfo
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
  std::int32_t MPV_GetPicAtr(std::int32_t decoderHandle, moho::SfmpvPictureDecodeLane* outPictureDecodeLane);
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
    const SfmpvDecodeFrameParam* decodeFrameParam
  );
  /**
   * Address: 0x00AF5F50 (FUN_00AF5F50, _mpvcmc_InitMcOiTa)
   *
   * What it does:
   * Seeds MPV CMC interpolation-pointer lanes to the internal table storage
   * block and resets per-lane span words.
   */
  Mpvcmc* mpvcmc_InitMcOiTa(Mpvcmc* mpvcmc);
  /**
   * Address: 0x00AF5FC0 (FUN_00AF5FC0, _MPVCMC_InitMcOiRt)
   *
   * What it does:
   * Initializes MPV CMC interpolation runtime words from fixed seed lanes in
   * the CMC object.
   */
  Mpvcmc* MPVCMC_InitMcOiRt(Mpvcmc* mpvcmc);
  /**
   * Address: 0x00AF6010 (FUN_00AF6010, _MPVCMC_SetCcnt)
   *
   * What it does:
   * Recomputes CMC count/state lanes from the runtime mode gate.
   */
  std::int32_t MPVCMC_SetCcnt(Mpvcmc* mpvcmc);
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
  std::int32_t MPVUMC_InitOutRfb(Mpvcmc* mpvcmc);
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
    moho::SfmpvPictureDecodeLane* pictureDecodeLane,
    char* delimiterCursor,
    std::int32_t* outPresentationPtsWords,
    std::int32_t* outReferenceErrorSeedWords,
    std::int32_t pictureChangedFlag
  );
  std::int64_t sfmpv_ComplementPts(
    moho::SofdecSfdWorkctrlSubobj* workctrl,
    SfmpvComplementPts* complementState,
    const moho::SfmpvPictureDecodeLane* pictureDecodeLane,
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
    moho::SofdecSfdWorkctrlSubobj* workctrl,
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
    moho::SfplyMovieInfo* destinationInfo,
    std::int32_t frameRateBase,
    const std::int32_t* frameInfoWords,
    std::int32_t vbvBufferBytes
  );
  std::int32_t sfmpv_SetFrmPara(
    std::int32_t workctrlAddress,
    const moho::SfmpvPictureDecodeLane* pictureDecodeLane,
    SfmpvDecodeFrameParam* decodeFrameParam,
    std::int32_t* outFrameObjectAddress
  );
  std::int32_t sfmpv_ReadRefErrCnt(
    std::int32_t workctrlAddress,
    const moho::SfmpvInfo* mpvInfo,
    std::int32_t* outErrorMajor,
    std::int32_t* outErrorMinor
  );
  std::int32_t sfmpv_SetFrmTime(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_CalcRepeatField(std::int32_t workctrlAddress, std::int32_t frameObjectAddress, std::int32_t resetHistory);
  std::int32_t sfmpv_ChkBufSiz(std::int32_t workctrlAddress, const std::int32_t* frameDimensions);
  std::int32_t sfmpv_CalcFrmTtu(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_ReadTcode(std::int32_t frameObjectAddress, moho::SfmpvPackedTimecode* outTimecodeLane);
  std::int32_t sfmpv_CalcFrmTime(std::int32_t workctrlAddress, std::int32_t frameObjectAddress);
  std::int32_t sfmpv_UpdateFlowCnt(std::int32_t workctrlAddress);
  std::int32_t sfmpv_RingAddRead(std::int32_t workctrlAddress, std::int32_t advanceCount);
  std::int32_t
  sfmpv_ReprocessShc(std::int32_t workctrlAddress, const std::int32_t* decoderHandleLane, std::int32_t* outReprocessed);
  std::int32_t sfmpv_GetHd(std::int32_t workctrlAddress);
  moho::SfmpvfFrameObject* SFMPVF_AllocFrm(std::int32_t workctrlAddress);
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

struct SfbufRingChunk
{
  std::uint8_t* bufferAddress = nullptr; // +0x00
  std::int32_t byteCount = 0; // +0x04
};

static_assert(
  offsetof(SfbufRingChunk, bufferAddress) == 0x00,
  "SfbufRingChunk::bufferAddress offset must be 0x00"
);
static_assert(offsetof(SfbufRingChunk, byteCount) == 0x04, "SfbufRingChunk::byteCount offset must be 0x04");
static_assert(sizeof(SfbufRingChunk) == 0x08, "SfbufRingChunk size must be 0x08");

struct SfbufRingCursorSnapshot
{
  SfbufRingChunk firstChunk{}; // +0x00
  SfbufRingChunk secondChunk{}; // +0x08
  std::int32_t reservedWords[3]{}; // +0x10
};

static_assert(
  offsetof(SfbufRingCursorSnapshot, firstChunk) == 0x00,
  "SfbufRingCursorSnapshot::firstChunk offset must be 0x00"
);
static_assert(
  offsetof(SfbufRingCursorSnapshot, secondChunk) == 0x08,
  "SfbufRingCursorSnapshot::secondChunk offset must be 0x08"
);
static_assert(
  offsetof(SfbufRingCursorSnapshot, reservedWords) == 0x10,
  "SfbufRingCursorSnapshot::reservedWords offset must be 0x10"
);
static_assert(sizeof(SfbufRingCursorSnapshot) == 0x1C, "SfbufRingCursorSnapshot size must be 0x1C");


struct SfmpvfFrameTiming
{
  std::uint8_t mUnknown00To0B[0x0C]{}; // +0x00
  moho::SfmpvTtu frameTtu{}; // +0x0C
  std::int32_t resolvedTimeMajor = 0; // +0x38
  std::int32_t resolvedTimeMinor = 0; // +0x3C
  std::uint8_t mUnknown40To4B[0x0C]{}; // +0x40
  std::int32_t frameStartTimeMajor = 0; // +0x4C
  std::int32_t frameEndTimeMajor = 0; // +0x50
};

static_assert(
  offsetof(SfmpvfFrameTiming, frameTtu) == 0x0C,
  "SfmpvfFrameTiming::frameTtu offset must be 0x0C"
);
static_assert(
  offsetof(SfmpvfFrameTiming, resolvedTimeMajor) == 0x38,
  "SfmpvfFrameTiming::resolvedTimeMajor offset must be 0x38"
);
static_assert(
  offsetof(SfmpvfFrameTiming, resolvedTimeMinor) == 0x3C,
  "SfmpvfFrameTiming::resolvedTimeMinor offset must be 0x3C"
);
static_assert(
  offsetof(SfmpvfFrameTiming, frameStartTimeMajor) == 0x4C,
  "SfmpvfFrameTiming::frameStartTimeMajor offset must be 0x4C"
);
static_assert(
  offsetof(SfmpvfFrameTiming, frameEndTimeMajor) == 0x50,
  "SfmpvfFrameTiming::frameEndTimeMajor offset must be 0x50"
);

struct SfmpvfFrameRepeat
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
  offsetof(SfmpvfFrameRepeat, historyOrdinal) == 0x14,
  "SfmpvfFrameRepeat::historyOrdinal offset must be 0x14"
);
static_assert(
  offsetof(SfmpvfFrameRepeat, pictureType) == 0x18,
  "SfmpvfFrameRepeat::pictureType offset must be 0x18"
);
static_assert(
  offsetof(SfmpvfFrameRepeat, repeatAccumulatorWord) == 0x2E,
  "SfmpvfFrameRepeat::repeatAccumulatorWord offset must be 0x2E"
);
static_assert(
  offsetof(SfmpvfFrameRepeat, decodeOrderIndex) == 0x70,
  "SfmpvfFrameRepeat::decodeOrderIndex offset must be 0x70"
);

struct SfmpvfTimecodeSource
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
  offsetof(SfmpvfTimecodeSource, word00) == 0x10,
  "SfmpvfTimecodeSource::word00 offset must be 0x10"
);
static_assert(
  offsetof(SfmpvfTimecodeSource, word18) == 0x28,
  "SfmpvfTimecodeSource::word18 offset must be 0x28"
);
static_assert(
  offsetof(SfmpvfTimecodeSource, word1C) == 0x2C,
  "SfmpvfTimecodeSource::word1C offset must be 0x2C"
);
static_assert(
  offsetof(SfmpvfTimecodeSource, repeatFieldCount) == 0x54,
  "SfmpvfTimecodeSource::repeatFieldCount offset must be 0x54"
);


/**
 * MPV picture-attribute lane filled by `MPV_GetPicAtr` and consumed by
 * timecode reform helpers.
 */
struct SfmpvPictureAttribute
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
  offsetof(SfmpvPictureAttribute, timecodeFrameRateIndex) == 0x10,
  "SfmpvPictureAttribute::timecodeFrameRateIndex offset must be 0x10"
);
static_assert(
  offsetof(SfmpvPictureAttribute, timecodeFrameOrdinal) == 0x14,
  "SfmpvPictureAttribute::timecodeFrameOrdinal offset must be 0x14"
);
static_assert(
  offsetof(SfmpvPictureAttribute, timecodeDropFrameMode) == 0x1C,
  "SfmpvPictureAttribute::timecodeDropFrameMode offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvPictureAttribute, pictureTimecodeBase) == 0x30,
  "SfmpvPictureAttribute::pictureTimecodeBase offset must be 0x30"
);
static_assert(
  offsetof(SfmpvPictureAttribute, pictureTimecodeDisableLatch) == 0x57,
  "SfmpvPictureAttribute::pictureTimecodeDisableLatch offset must be 0x57"
);


/**
 * Decode-frame parameter block consumed by `MPV_DecodeFrmSj`.
 */
struct SfmpvDecodeFrameParam
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
  offsetof(SfmpvDecodeFrameParam, decodedFrameBaseAddress) == 0x20,
  "SfmpvDecodeFrameParam::decodedFrameBaseAddress offset must be 0x20"
);
static_assert(
  offsetof(SfmpvDecodeFrameParam, pictureDecodeLaneAddress) == 0x24,
  "SfmpvDecodeFrameParam::pictureDecodeLaneAddress offset must be 0x24"
);
static_assert(
  sizeof(SfmpvDecodeFrameParam) == 0x30,
  "SfmpvDecodeFrameParam size must be 0x30"
);



// The timing-lane extent is settled (see the note on the member), so every
// offset past it is checkable again.


struct SfmpvfFrameInfo
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
  offsetof(SfmpvfFrameInfo, pictureWidthPixels) == 0x00,
  "SfmpvfFrameInfo::pictureWidthPixels offset must be 0x00"
);
static_assert(
  offsetof(SfmpvfFrameInfo, pictureType) == 0x10,
  "SfmpvfFrameInfo::pictureType offset must be 0x10"
);
static_assert(
  offsetof(SfmpvfFrameInfo, presentationTimeMajor) == 0x14,
  "SfmpvfFrameInfo::presentationTimeMajor offset must be 0x14"
);
static_assert(
  offsetof(SfmpvfFrameInfo, presentationTimeMinor) == 0x18,
  "SfmpvfFrameInfo::presentationTimeMinor offset must be 0x18"
);
static_assert(
  offsetof(SfmpvfFrameInfo, decodeConditionMode) == 0x1C,
  "SfmpvfFrameInfo::decodeConditionMode offset must be 0x1C"
);
static_assert(
  offsetof(SfmpvfFrameInfo, pictureUserInfoAddress) == 0x38,
  "SfmpvfFrameInfo::pictureUserInfoAddress offset must be 0x38"
);
static_assert(
  offsetof(SfmpvfFrameInfo, chromaLayoutClass) == 0x48,
  "SfmpvfFrameInfo::chromaLayoutClass offset must be 0x48"
);
static_assert(
  offsetof(SfmpvfFrameInfo, referenceErrorSeedMajor) == 0x50,
  "SfmpvfFrameInfo::referenceErrorSeedMajor offset must be 0x50"
);
static_assert(
  offsetof(SfmpvfFrameInfo, referenceUpdateMode) == 0x58,
  "SfmpvfFrameInfo::referenceUpdateMode offset must be 0x58"
);
static_assert(
  offsetof(SfmpvfFrameInfo, pictureDetailWord68) == 0x68,
  "SfmpvfFrameInfo::pictureDetailWord68 offset must be 0x68"
);
static_assert(
  offsetof(SfmpvfFrameInfo, pictureDecodeFlagA) == 0x6C,
  "SfmpvfFrameInfo::pictureDecodeFlagA offset must be 0x6C"
);
static_assert(
  offsetof(SfmpvfFrameInfo, pictureDecodeFlagO) == 0x7A,
  "SfmpvfFrameInfo::pictureDecodeFlagO offset must be 0x7A"
);


struct SfmpvHeader
{
  std::int32_t hasHeader = 0; // +0x00
  std::int32_t frameRateTicks = 0; // +0x04
  std::int32_t frameRateMode = 0; // +0x08
  std::uint32_t concatTimeSeedWords[11]{}; // +0x0C
  std::uint8_t pictureAttributeBytes[0x200]{}; // +0x38
  std::int32_t pictureAttributeByteCount = 0; // +0x238
};

static_assert(
  offsetof(SfmpvHeader, concatTimeSeedWords) == 0x0C,
  "SfmpvHeader::concatTimeSeedWords offset must be 0x0C"
);
static_assert(
  offsetof(SfmpvHeader, pictureAttributeBytes) == 0x38,
  "SfmpvHeader::pictureAttributeBytes offset must be 0x38"
);
static_assert(
  offsetof(SfmpvHeader, pictureAttributeByteCount) == 0x238,
  "SfmpvHeader::pictureAttributeByteCount offset must be 0x238"
);

struct SfmpvDefectLane
{
  std::uint8_t mUnknown00To17[0x18]{}; // +0x00
  std::int32_t pictureType = 0; // +0x18
};

static_assert(
  offsetof(SfmpvDefectLane, pictureType) == 0x18,
  "SfmpvDefectLane::pictureType offset must be 0x18"
);

struct SfmpvAudioTransportVtable
{
  void(__cdecl* reserved00)() = nullptr; // +0x00
  void(__cdecl* reserved04)() = nullptr; // +0x04
  void(__cdecl* reserved08)() = nullptr; // +0x08
  void(__cdecl* readTotalSamplesProc)() = nullptr; // +0x0C
};

struct SfmpvAudioTransport
{
  SfmpvAudioTransportVtable* vtable = nullptr; // +0x00
};

static_assert(
  offsetof(SfmpvAudioTransport, vtable) == 0x00,
  "SfmpvAudioTransport::vtable offset must be 0x00"
);

struct SfmpvStreamWindowCursor
{
  std::uint8_t* cursor = nullptr; // +0x00
  std::int32_t byteCount = 0; // +0x04
};

static_assert(
  sizeof(SfmpvStreamWindowCursor) == 0x08,
  "SfmpvStreamWindowCursor size must be 0x08"
);

using SfmpvStreamBufferReadWindowProc = void(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t laneIndex,
  std::int32_t byteCount,
  SfmpvStreamWindowCursor* cursorWindow
);
using SfmpvStreamBufferCommitWindowProc = std::int32_t(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t laneIndex,
  SfmpvStreamWindowCursor* cursorWindow
);
using SfmpvStreamBufferAdvanceWindowProc = void(__cdecl*)(
  std::int32_t streamBufferAddress,
  std::int32_t discardMode,
  SfmpvStreamWindowCursor* cursorWindow
);

struct SfmpvStreamBufferVtable
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

struct SfmpvStreamBuffer
{
  SfmpvStreamBufferVtable* vtable = nullptr; // +0x00
};

static_assert(
  offsetof(SfmpvStreamBuffer, vtable) == 0x00,
  "SfmpvStreamBuffer::vtable offset must be 0x00"
);

/**
 * Runtime lane used by MPV CMC motion-compensation init helpers.
 */
struct Mpvcmc
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

static_assert(offsetof(Mpvcmc, initWord120) == 0x120, "Mpvcmc::initWord120 offset must be 0x120");
static_assert(offsetof(Mpvcmc, initWord128) == 0x128, "Mpvcmc::initWord128 offset must be 0x128");
static_assert(offsetof(Mpvcmc, initWord130) == 0x130, "Mpvcmc::initWord130 offset must be 0x130");
static_assert(offsetof(Mpvcmc, initWord138) == 0x138, "Mpvcmc::initWord138 offset must be 0x138");
static_assert(offsetof(Mpvcmc, initWord140) == 0x140, "Mpvcmc::initWord140 offset must be 0x140");
static_assert(offsetof(Mpvcmc, initWord148) == 0x148, "Mpvcmc::initWord148 offset must be 0x148");
static_assert(offsetof(Mpvcmc, initWord150) == 0x150, "Mpvcmc::initWord150 offset must be 0x150");
static_assert(offsetof(Mpvcmc, initWord154) == 0x154, "Mpvcmc::initWord154 offset must be 0x154");
static_assert(offsetof(Mpvcmc, initWord158) == 0x158, "Mpvcmc::initWord158 offset must be 0x158");
static_assert(offsetof(Mpvcmc, initWord15C) == 0x15C, "Mpvcmc::initWord15C offset must be 0x15C");
static_assert(offsetof(Mpvcmc, initWord160) == 0x160, "Mpvcmc::initWord160 offset must be 0x160");
static_assert(offsetof(Mpvcmc, initWord164) == 0x164, "Mpvcmc::initWord164 offset must be 0x164");
static_assert(offsetof(Mpvcmc, initWord168) == 0x168, "Mpvcmc::initWord168 offset must be 0x168");
static_assert(offsetof(Mpvcmc, initWord16C) == 0x16C, "Mpvcmc::initWord16C offset must be 0x16C");
static_assert(offsetof(Mpvcmc, initWord170) == 0x170, "Mpvcmc::initWord170 offset must be 0x170");
static_assert(offsetof(Mpvcmc, initWord174) == 0x174, "Mpvcmc::initWord174 offset must be 0x174");
static_assert(offsetof(Mpvcmc, initWord178) == 0x178, "Mpvcmc::initWord178 offset must be 0x178");
static_assert(offsetof(Mpvcmc, initWord17C) == 0x17C, "Mpvcmc::initWord17C offset must be 0x17C");
static_assert(offsetof(Mpvcmc, initWord180) == 0x180, "Mpvcmc::initWord180 offset must be 0x180");
static_assert(offsetof(Mpvcmc, initWord184) == 0x184, "Mpvcmc::initWord184 offset must be 0x184");
static_assert(offsetof(Mpvcmc, initWord1A4) == 0x1A4, "Mpvcmc::initWord1A4 offset must be 0x1A4");
static_assert(offsetof(Mpvcmc, umcHalfResMode) == 0x1B8, "Mpvcmc::umcHalfResMode offset must be 0x1B8");
static_assert(
  offsetof(Mpvcmc, outputWidthPixels) == 0x1D0,
  "Mpvcmc::outputWidthPixels offset must be 0x1D0"
);
static_assert(
  offsetof(Mpvcmc, outputHeightPixels) == 0x1D4,
  "Mpvcmc::outputHeightPixels offset must be 0x1D4"
);
static_assert(offsetof(Mpvcmc, initWord280) == 0x280, "Mpvcmc::initWord280 offset must be 0x280");
static_assert(offsetof(Mpvcmc, initWord282) == 0x282, "Mpvcmc::initWord282 offset must be 0x282");
static_assert(
  offsetof(Mpvcmc, outputRfbBaseAddress) == 0x284,
  "Mpvcmc::outputRfbBaseAddress offset must be 0x284"
);
static_assert(
  offsetof(Mpvcmc, outputYPlaneAddress) == 0x294,
  "Mpvcmc::outputYPlaneAddress offset must be 0x294"
);
static_assert(
  offsetof(Mpvcmc, outputCPlaneAddress) == 0x298,
  "Mpvcmc::outputCPlaneAddress offset must be 0x298"
);
static_assert(
  offsetof(Mpvcmc, outputYPlaneBaseAddress) == 0x29C,
  "Mpvcmc::outputYPlaneBaseAddress offset must be 0x29C"
);
static_assert(
  offsetof(Mpvcmc, outputChromaStrideBytes) == 0x2A0,
  "Mpvcmc::outputChromaStrideBytes offset must be 0x2A0"
);
static_assert(
  offsetof(Mpvcmc, outputLumaStrideBytes) == 0x2A2,
  "Mpvcmc::outputLumaStrideBytes offset must be 0x2A2"
);
static_assert(offsetof(Mpvcmc, initWord0D20) == 0xD20, "Mpvcmc::initWord0D20 offset must be 0xD20");

// ---------------------------------------------------------------------------
// Global CRI MPV state variables (BSS)
// ---------------------------------------------------------------------------

extern "C" {
  extern std::int32_t SFTIM_prate[];

  /**
   * Address: 0x00D7F60C
   *
   * Nominal integer frame rate per MPEG `frame_rate_code`, i.e. the number of
   * frames a timecode second holds. `sfmpv_Pts2Tc` and `sfmpv_NextTc` divide by
   * it, so index `0` (the forbidden code) must never reach them.
   */
  std::int32_t sfmpv_fps_round[9] = { 0, 24, 24, 25, 30, 30, 50, 60, 60 };

  /**
   * Address: 0x00D7F630 / 0x00D7F650
   *
   * SMPTE drop-frame conversion constants for the two 1000/1001 rates, laid out
   * as `SfmpvDropFrameConversionTable`: cycle (one hour), ten-minute chunk,
   * first-minute threshold, drop-minute length, drop-minute head, frames per
   * second, minutes per chunk, and the head frame number that a drop minute
   * starts on (`02` at 29.97, `04` at 59.94).
   */
  std::int32_t sfmpv_conv_29_97[8] = { 107892, 17982, 1800, 1798, 28, 30, 10, 2 };
  std::int32_t sfmpv_conv_59_94[8] = { 215784, 35964, 3600, 3596, 56, 60, 10, 4 };

  extern SfmpvPara sfmpv_para;
  extern std::int32_t sfmpv_rfb_adr_tbl[2];
  extern std::uint8_t sfmpv_work[];
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
  constexpr std::int32_t kSfmpvErrCreateFailed = -16773366; // 0xFF000F0A
  constexpr std::int32_t kSfmpvErrSetErrFuncFailed = -16773365; // 0xFF000F0B

  /**
   * Reference-frame-buffer address entries. The binary bounds its walks of
   * `sfmpv_rfb_adr_tbl` (0x00FB9CA8) with `offset _sfmpv_work` (0x00FB9CB0),
   * i.e. the table is exactly the eight bytes between the two symbols.
   */
  constexpr std::int32_t kSfmpvRfbAddressTableCount = 2;

  /** Frame-pool entries `sfmpvf_CheckMpvPara` accepts and `SFD_SetMpvParaTbl` writes. */
  constexpr std::int32_t kSfmpvMaxFramePoolCount = 16;
  constexpr std::int32_t kSfmpvErrWriteApiUnsupported = -16773363; // 0xFF000F0D
  constexpr std::int32_t kSfmpvErrFrameBufferTooSmall = -16773353; // 0xFF000F17

  template <typename T>
  [[nodiscard]] T* AddressToPointer(const std::int32_t address) noexcept
  {
    return reinterpret_cast<T*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  /**
   * MPV condition slots 1, 2 and 6 carry callback addresses, but the workctrl
   * stores them - and `SFSET_GetCond` returns them - as plain words. The
   * binary hands the word straight to `MPV_SetCond`; this makes that
   * reinterpretation explicit rather than leaving a bare cast at each site.
   */
  [[nodiscard]] std::int32_t (*AsMpvConditionCallback(const std::int32_t conditionWord) noexcept)()
  {
    return reinterpret_cast<std::int32_t (*)()>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(conditionWord)));
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

  [[nodiscard]] moho::SfbufSupplyLane*
  GetSfptsSourceLane(moho::SofdecSfdWorkctrlSubobj* const workctrl, const std::int32_t sourceLaneIndex) noexcept
  {
    return &workctrl->bufferState.supplyLanes[sourceLaneIndex];
  }

  void AddSigned32ToLane(std::int64_t* const counter, const std::int32_t delta) noexcept
  {
    *counter += static_cast<std::int64_t>(delta);
  }

  [[nodiscard]] std::int32_t FlowWordLow(const std::int64_t counter) noexcept
  {
    return static_cast<std::int32_t>(counter);
  }

  [[nodiscard]] std::int32_t FlowWordHigh(const std::int64_t counter) noexcept
  {
    return static_cast<std::int32_t>(counter >> 32);
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
  auto* const timingLane = static_cast<moho::SfmpvTimingLaneTail*>(timerState);
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
  const auto* const timingLane = static_cast<const moho::SfmpvTimingLaneTail*>(timerState);
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
 * `nfrmPoolWork` tab entries.
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

  for (std::int32_t tableIndex = 0; tableIndex < kSfmpvRfbAddressTableCount; ++tableIndex) {
    sfmpv_rfb_adr_tbl[tableIndex] = AlignAddressTo0x800(ringFrameBufferAddressTable[tableIndex]);
  }

  for (std::int32_t tabIndex = 0; tabIndex < kSfmpvMaxFramePoolCount; ++tabIndex) {
    if (tabIndex >= parameterTable->nfrmPoolWork) {
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  auto* const picUsrState = reinterpret_cast<std::uint32_t*>(&mpvInfo->pictureUserBufferAddress);

  if (userBufferAddress != 0 && frameSlotCount != 0 && bytesPerFrame != 0) {
    if (frameSlotCount < (workctrl->createTemplate.framePoolWork + 3)) {
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
    return SFD_SetMpvCond(AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress), 5, cond5Arg);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  SfbufRingChunk pictureRange{};
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
Mpvcmc* mpvcmc_InitMcOiTa(Mpvcmc* const mc)
{
  mc->initWord154 = (mc->initWord1A4 != 0) ? 4 : -1;

  const std::int32_t tableAddress = PointerToAddress(&mc->initWord0D20);
  mc->initWord158 = tableAddress;
  mc->initWord160 = tableAddress;
  mc->initWord168 = tableAddress;
  mc->initWord170 = tableAddress;
  mc->initWord178 = tableAddress;
  mc->initWord180 = tableAddress;

  mc->initWord15C = 8;
  mc->initWord164 = 8;
  mc->initWord16C = 8;
  mc->initWord174 = 8;
  mc->initWord17C = 8;
  mc->initWord184 = 8;
  return mc;
}

/**
 * Address: 0x00AF5FC0 (FUN_00AF5FC0, _MPVCMC_InitMcOiRt)
 *
 * What it does:
 * Initializes MPV CMC interpolation runtime words from fixed seed lanes in
 * the CMC object.
 */
Mpvcmc* MPVCMC_InitMcOiRt(Mpvcmc* const mc)
{
  mc->initWord120 = (mc->initWord1A4 != 0) ? 4 : -1;

  const std::int32_t seedWord0 = mc->initWord280;
  mc->initWord128 = seedWord0;
  mc->initWord130 = seedWord0;

  const std::int32_t seedWord1 = mc->initWord282;
  mc->initWord138 = seedWord1;
  mc->initWord140 = seedWord1;
  mc->initWord148 = seedWord1;
  mc->initWord150 = seedWord1;
  return mc;
}

/**
 * Address: 0x00AF6010 (FUN_00AF6010, _MPVCMC_SetCcnt)
 *
 * What it does:
 * Recomputes CMC count/state lanes from the runtime mode gate.
 */
extern "C" std::int32_t MPVCMC_SetCcnt(Mpvcmc* const mc)
{
  const std::int32_t nextCount = (mc->initWord1A4 != 0) ? 4 : -1;
  mc->initWord154 = nextCount;
  mc->initWord120 = nextCount;
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
extern "C" std::int32_t MPVUMC_InitOutRfb(Mpvcmc* const mc)
{
  std::int32_t widthPixels = mc->outputWidthPixels;
  std::int32_t heightPixels = mc->outputHeightPixels;
  const std::int32_t outputRfbBaseAddress = mc->outputRfbBaseAddress;

  if (mc->umcHalfResMode != 0) {
    widthPixels = RoundUpDivPow2Signed(widthPixels, 3);
    heightPixels = RoundUpDivPow2Signed(heightPixels, 3);
  }

  mc->outputYPlaneBaseAddress = outputRfbBaseAddress;

  const std::int32_t alignedLumaWidth = RoundUpDivPow2Signed(widthPixels, 4) << 4;
  const std::int32_t lumaStrideUnits = RoundUpDivPow2Signed(alignedLumaWidth, 5);
  mc->outputLumaStrideBytes = static_cast<std::int16_t>(lumaStrideUnits << 5);

  const std::int32_t alignedChromaHalfWidth = Div2TowardZero(alignedLumaWidth);
  const std::int32_t chromaStrideUnits = RoundUpDivPow2Signed(alignedChromaHalfWidth, 5);
  mc->outputChromaStrideBytes = static_cast<std::int16_t>(chromaStrideUnits << 5);

  const std::int32_t macroblockRows = RoundUpDivPow2Signed(heightPixels, 5);
  const std::int32_t outputYPlaneAddress = outputRfbBaseAddress + ((lumaStrideUnits * macroblockRows) << 10);
  mc->outputYPlaneAddress = outputYPlaneAddress;

  const std::int32_t macroblockRowBytes = macroblockRows << 5;
  const std::int32_t halfMacroblockRowBytes = Div2TowardZero(macroblockRowBytes);
  const std::int32_t outputCPlaneAddress =
    outputYPlaneAddress + (((halfMacroblockRowBytes * chromaStrideUnits) << 5));
  mc->outputCPlaneAddress = outputCPlaneAddress;
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

/** Decoder slots SFMPV asks `MPV_Init` for (`push 20h` at 0x00AD1B79). */
constexpr std::int32_t kSfmpvMpvObjectCount = 32;

/**
 * Address: 0x00FB9CB0 (`_sfmpv_work`, `.data` BSS)
 *
 * The MPV library's whole work arena. `mpvlib_InitWork` aligns the base up to
 * 32 bytes and then clears `(objectCount + 1) << 13` bytes of it, so this must
 * be at least that large - the `alignas` makes the alignment step a no-op and
 * removes the need for slack. The layout MPV then carves out of it (32 object
 * slots of 0x13C0, the conceal state, the VLC lanes, the clip mirror and the
 * DCT scale table) all sits well inside that span.
 *
 * The binary only ever takes this symbol's address: `SFMPV_Init` passes it to
 * `MPV_Init`, and `SFD_SetMpvParaTbl` / `sfmpv_CheckMpvPara` compare pointers
 * against it. Nothing indexes it, so the cleared span is what fixes the size.
 */
alignas(32) std::uint8_t sfmpv_work[(kSfmpvMpvObjectCount + 1) << 13] = {};

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

  const std::int32_t initResult = MPV_Init(kSfmpvMpvObjectCount, reinterpret_cast<std::int32_t>(sfmpv_work));
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
 * Address: 0x00AD1C10 (FUN_00AD1C10, _sfmpv_ExecServerSub)
 *
 * IDA signature:
 * int __cdecl sfmpv_ExecServerSub(int a1);
 *
 * What it does:
 * One MPV decode-server tick. Skips entirely when the video condition lane is
 * off, and reports "no work" once the destination side has terminated.
 * Otherwise it refreshes the Y16 colour-type condition, runs the auxiliary
 * sequence-header pass while the player is still in the PREP stage, decodes as
 * many pictures as the ring and frame pool allow, and finally latches the MPV
 * prep and term flags - the prep latch is what raises SFBUF's prep flag for the
 * video-output lane, which is how SFPLY learns that PREP is complete.
 */
std::int32_t sfmpv_ExecServerSub(const std::int32_t workctrlAddress)
{
  constexpr std::int32_t kSfsetCondVideo = 5;
  constexpr std::int32_t kSfplyExecutionStagePrep = 2;

  const std::int32_t videoCondition = SFSET_GetCond(workctrlAddress, kSfsetCondVideo);
  if (videoCondition == 0) {
    return videoCondition;
  }
  if (sfmpv_GetTermDst(workctrlAddress) == 1) {
    return 0;
  }

  (void)sfmpv_SetCondY16(workctrlAddress);

  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  if (workctrl->handleState == kSfplyExecutionStagePrep) {
    (void)sfmpv_ProcessAuxShc(workctrlAddress);
  }

  const std::int32_t decodedPictureResult = sfmpv_DecodeSomePic(workctrlAddress);
  (void)sfmpv_ChkPrepFlg(workctrlAddress);
  (void)sfmpv_ChkTermFlg(workctrlAddress);
  return decodedPictureResult;
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
  if (sfmpv_para.nfrmPoolWork <= 0 || sfmpv_para.nfrmPoolWork > kSfmpvMaxFramePoolCount) {
    return -1;
  }

  if (sfmpv_para.val4 != 0 && sfmpv_para.val8 != 0) {
    return 0;
  }

  // Every reference-frame-buffer entry must be populated. The binary walks the
  // table until the cursor reaches `sfmpv_work`, which is simply the next
  // symbol in BSS (_sfmpv_rfb_adr_tbl 0x00FB9CA8, _sfmpv_work 0x00FB9CB0) - an
  // end-of-table sentinel, not a bound with any meaning of its own. Our two
  // symbols live in different translation units, so the comparison has to be
  // expressed as what it actually measured: the table's own extent.
  for (std::int32_t index = 0; index < kSfmpvRfbAddressTableCount; ++index) {
    if (sfmpv_rfb_adr_tbl[index] == 0) {
      return -1;
    }
  }

  for (std::int32_t index = 0; index < sfmpv_para.nfrmPoolWork; ++index) {
    if (sSofDec_tabs[index] == 0) {
      return -1;
    }
  }
  return 0;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
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

  const std::int32_t streamLane = (SFTRN_IsSetup(AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress), 1) == 0) ? 1 : 0;
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t ringIndex = workctrl->transferState.transfer.demux.prepSourceLaneIndex;
  const std::int32_t ringBufferBytes = SFBUF_GetRingBufSiz(workctrlAddress, ringIndex);
  const std::int32_t readableBytes = SFBUF_RingGetDataSiz(workctrlAddress, ringIndex);
  if ((readableBytes - ringBufferBytes) >= workctrl->createTemplate.packBytes) {
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  for (std::int32_t frameIndex = 0; frameIndex < mpvInfo->frameObjectCount; ++frameIndex) {
    const moho::SfmpvfFrameObject& frameObject = mpvInfo->frameObjects[frameIndex];
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
  const moho::SfmpvfFrameObject* const selectedFrameObject,
  const moho::SfmpvfFrameObject* const candidateFrameObject
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

  moho::SfmpvfFrameObject* selectedFrameObject = nullptr;
  std::int32_t selectableFrameCount = 0;

  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  std::int32_t requiredFrameCount = workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionPrepFrameRequiredCount];
  if (requiredFrameCount == -1 || workctrl->createTemplate.framePoolWork < requiredFrameCount) {
    requiredFrameCount = workctrl->createTemplate.framePoolWork;
  }

  std::int32_t preparedFrameCount = SFMPVF_GetNumFrm(workctrlAddress);
  if (workctrl->decodePathMode == 2) {
    preparedFrameCount += workctrl->playbackInfo.preparedFrameCount;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t prepDestinationLaneIndex = workctrl->transferState.transfer.demux.prepDestinationLaneIndex;
  const std::int32_t prepSourceLaneIndex = workctrl->transferState.transfer.demux.prepSourceLaneIndex;

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  if (SFMPVF_IsTermDec(workctrlAddress) == 0) {
    return 0;
  }
  if (frameCount == 0) {
    return 1;
  }

  if (
    workctrl->decodePathMode == 1 && frameCount == 1
    && workctrl->playbackInfo.preparedFrameCount > workctrl->playbackInfo.consumedFrameCount
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  return SFBUF_SetTermFlg(workctrlAddress, workctrl->transferState.transfer.demux.prepDestinationLaneIndex, termFlag);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t frameCount = SFMPVF_GetNumFrm(workctrlAddress);

  if (frameCount == -1 || sfmpv_IsFinalFrmGotten(workctrlAddress, frameCount) != 0) {
    (void)sfmpv_SetTermDst(workctrlAddress, 1);
    if (workctrl->playbackInfo.publishedAddress == 0) {
      return SFSET_SetCond(workctrlAddress, 5, 0);
    }
    return workctrl->playbackInfo.publishedAddress;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  SfbufRingCursorSnapshot ringCursor{};
  const std::int32_t sourceLaneIndex = workctrl->transferState.transfer.demux.prepSourceLaneIndex;

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

  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshot*>(ringCursorSnapshotWords);
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
      // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
      std::memcpy(delimiterProbe, primaryDelimiter, sizeof(delimiterProbe));
    } else {
      return 1;
    }
  } else {
    const std::int32_t seamBytes =
      static_cast<std::int32_t>(primaryAddress - firstAddress - static_cast<std::uint32_t>(firstLength) + 4u);
    if (seamBytes <= 0) {
      // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
      std::memcpy(delimiterProbe, primaryDelimiter, sizeof(delimiterProbe));
    } else {
      if (seamBytes > secondLength) {
        return 1;
      }
      const std::int32_t firstBytes = 4 - seamBytes;
      // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
      std::memcpy(delimiterProbe, primaryDelimiter, static_cast<std::size_t>(firstBytes));
      // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshot*>(ringCursorSnapshotWords);
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
  const auto* const ringCursor = AddressToPointer<const SfbufRingCursorSnapshot>(ringCursorSnapshotAddress);
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
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(
    seamWindow,
    ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes,
    static_cast<std::size_t>(firstBridgeBytes)
  );
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  const auto* const ringCursor = reinterpret_cast<const SfbufRingCursorSnapshot*>(ringCursorSnapshotWords);
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
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
    std::memcpy(
      seamWindow,
      ringCursor->firstChunk.bufferAddress + ringCursor->firstChunk.byteCount - firstBridgeBytes,
      static_cast<std::size_t>(firstBridgeBytes)
    );
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
struct SfmpvPictureAttribute;
std::int32_t sfmpv_ReformTc(
    std::int32_t workctrlAddress,
    SfmpvPictureAttribute* pictureAttribute,
    std::int64_t presentationPts,
    std::int32_t detectErrorMode);
std::int32_t sfmpv_IsLate(std::int32_t workctrlAddress, std::int32_t updateMode);
std::int32_t sfmpv_ErrFn(std::int32_t workctrlAddress, std::int32_t statusCode);

/**
 * Address: 0x00AD2690 (FUN_00AD2690, _sfmpv_DecodeOneUnit)
 *
 * What it does:
 * Executes one delimiter-scoped decode step, including seek/endcode handling,
 * picture-attribute decode lane, and frame decode-or-skip dispatch.
 */
std::int32_t sfmpv_DecodeOneUnit(
  moho::SofdecSfdWorkctrlSubobj* const workctrl,
  const std::int32_t activeSize,
  const std::int32_t delimiterState,
  const std::int32_t hasActiveUnit,
  std::int32_t* const outUnitProcessed
)
{
  const std::int32_t workctrlAddress = PointerToAddress(workctrl);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  *outUnitProcessed = 0;
  workctrl->playbackInfo.decodeStarvedLatch = 0;

  std::int32_t activeDelimiterMask = delimiterState;
  if (mpvInfo->concatControlFlags != 0xCC || mpvInfo->picAtrPrimedLatch == 0) {
    activeDelimiterMask &= 0xCC;
  }

  std::int32_t streamBufferAddress = 0;
  std::int32_t decodeResult = SFBUF_RingGetSj(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex, &streamBufferAddress);
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
      workctrl->playbackInfo.decodeStarvedLatch = 1;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  if (workctrl->transferState.transfer.demux.seekFixedReadTotal < 0) {
    workctrl->transferState.transfer.demux.seekFixedReadTotal = SFBUF_GetRTot(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex) + 4;
  }

  if (workctrl->timingLane.seekFixedBaselineTtu.timeMajor < 0) {
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
    std::memcpy(
      &workctrl->timingLane.seekFixedBaselineTtu,
      &workctrl->timingLane.concatAudioTimeUnit[0],
      sizeof(moho::SfmpvTtu)
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const auto* const concatAudioTtu =
    reinterpret_cast<const moho::SfmpvTtu*>(workctrl->timingLane.concatAudioTimeUnit);
  if (concatAudioTtu->state == 0) {
    return 0;
  }

  moho::SfmpvPackedTimecode nextTimecode{};
  (void)sfmpv_NextTc(
    reinterpret_cast<const moho::SfmpvPackedTimecode*>(concatAudioTtu->packedTimecodeWords),
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  std::int32_t totalSamples = 0;
  std::int32_t sampleRate = 44100;
  const auto* const transportView = AddressToPointer<const SfmpvAudioTransport>(workctrlAddress);
  if (transportView->vtable->readTotalSamplesProc == &SFD_tr_ad_adxt) {
    if (SFCON_ReadTotSmplQue(workctrlAddress, &totalSamples, &sampleRate) == 0) {
      return -1;
    }
  }

  totalSamples += workctrl->timerTail.audioTotalSampleCount;
  workctrl->timerTail.audioTotalSampleCount = totalSamples;

  const std::int32_t concatAudioTime =
    UTY_MulDiv(totalSamples, static_cast<std::int32_t>(workctrl->timingLane.concatVideoTimeUnit[10]), sampleRate)
    - workctrl->timerTail.decodeProgressTime;
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
  const moho::SfptsPtsQueue* const ptsQueue,
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

  const auto* const entries = AddressToPointer<const moho::SfptsQueueEntry>(ptsQueue->entriesBaseAddress);
  std::int32_t byteOffset = entryIndex * static_cast<std::int32_t>(sizeof(moho::SfptsQueueEntry));
  const std::int32_t ringByteSpan = entryCapacity * static_cast<std::int32_t>(sizeof(moho::SfptsQueueEntry));

  while (true) {
    const auto* const entry = reinterpret_cast<const moho::SfptsQueueEntry*>(
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
    byteOffset += static_cast<std::int32_t>(sizeof(moho::SfptsQueueEntry));

    ++queueOffset;
    if (queueOffset >= queuedEntryCount) {
      return -1;
    }
  }
}

/**
 * Address: 0x00AE5CA0 (FUN_00AE5CA0, _sfpts_ReadPtsQueSub)
 *
 * moho::SfptsPtsQueue *,int,int *,int,int
 *
 * What it does:
 * Searches one source-lane PTS queue for the delimiter-relative entry, updates
 * queue cursor/count state, and copies one 16-byte entry payload.
 */
std::int32_t* sfpts_ReadPtsQueSub(
  moho::SfptsPtsQueue* const ptsQueue,
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

      const auto* const entries = AddressToPointer<const moho::SfptsQueueEntry>(ptsQueue->entriesBaseAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t updatedConcatTime = workctrl->timerTail.decodeProgressTime + totalTime;
  workctrl->timerTail.decodeProgressTime = updatedConcatTime;

  const std::int32_t nextWriteOrdinal = workctrl->timerTail.concatTimeHistoryWriteOrdinal + 1;
  workctrl->timerTail.concatTimeHistory[Modulo32Index(nextWriteOrdinal)] = updatedConcatTime;
  workctrl->timerTail.concatTimeHistoryWriteOrdinal = nextWriteOrdinal;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t queuedCount = workctrl->timerTail.totalSampleQueueWriteOrdinal - workctrl->timerTail.totalSampleQueueReadOrdinal;
  if (queuedCount >= 32) {
    SFLIB_UnlockCs();
    return 0;
  }

  workctrl->timerTail.queuedAudioSampleRate = sampleRate;
  workctrl->timerTail.totalSampleQueueTotals[Modulo32Index(workctrl->timerTail.totalSampleQueueWriteOrdinal)] = totalSamples;
  ++workctrl->timerTail.totalSampleQueueWriteOrdinal;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  SFLIB_LockCs();
  const std::int32_t queuedCount = workctrl->timerTail.totalSampleQueueWriteOrdinal - workctrl->timerTail.totalSampleQueueReadOrdinal;
  if (queuedCount <= 0) {
    *outTotalSamples = -1;
    SFLIB_UnlockCs();
    return 0;
  }

  *outSampleRate = workctrl->timerTail.queuedAudioSampleRate;
  *outTotalSamples = workctrl->timerTail.totalSampleQueueTotals[Modulo32Index(workctrl->timerTail.totalSampleQueueReadOrdinal)];
  ++workctrl->timerTail.totalSampleQueueReadOrdinal;
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
  const auto* const streamBuffer = AddressToPointer<const SfmpvStreamBuffer>(streamBufferAddress);
  SfmpvStreamWindowCursor cursorWindow{};

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  (void)SFBUF_AddRtotSj(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex, consumedBytes);
  AddSigned32ToLane(&workctrl->playbackInfo.flowCounter1.consumedBytes, consumedBytes);
  return FlowWordHigh(workctrl->playbackInfo.flowCounter1.consumedBytes);
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
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  SfbufRingCursorSnapshot ringCursor{};
  if (
    SFBUF_RingGetRead(
      workctrlAddress,
      workctrl->transferState.transfer.demux.prepSourceLaneIndex,
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
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  return SFBUF_GetTermFlg(workctrlAddress, workctrl->transferState.transfer.demux.prepDestinationLaneIndex);
}

/**
 * Address: 0x00AD2C30 (FUN_00AD2C30, _sfmpv_GetTermSrc)
 *
 * What it does:
 * Returns source-lane terminal flag from the active prep source ring.
 */
std::int32_t sfmpv_GetTermSrc(const std::int32_t workctrlAddress)
{
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  return SFBUF_GetTermFlg(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex);
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

  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  auto* const pictureDecodeLane = &mpvInfo->pictureDecodeLane;
  const auto* const chunk = reinterpret_cast<const SfbufRingChunk*>(chunkWords);

  mpvInfo->pictureUserFlags = 0;
  MPV_SetPicUsrBuf(
    mpvInfo->decoderHandle,
    mpvInfo->pictureUserBufferMirrorAddress,
    mpvInfo->pictureUserBufferSize
  );

  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1);
  *outDecodeState = MPV_DecodePicAtrSj(mpvInfo->decoderHandle, streamBufferAddress);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1) - flowCountBefore;

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
      workctrl->movieInfo.pictureWidthPixels > 0
      && (workctrl->movieInfo.pictureWidthPixels != pictureDecodeLane->pictureWidthPixels
          || workctrl->movieInfo.pictureHeightPixels != pictureDecodeLane->pictureHeightPixels)
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
  } else if (workctrl->createTemplate.bufferFormat == 3 && mpvInfo->secondaryReferenceFrameObjectAddress != 0) {
    const auto* const secondaryReferenceFrame =
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->secondaryReferenceFrameObjectAddress);
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
    reinterpret_cast<SfmpvPictureAttribute*>(pictureDecodeLane),
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
  moho::SofdecSfdWorkctrlSubobj* const workctrl,
  SfmpvComplementPts* const complementState,
  const moho::SfmpvPictureDecodeLane* const pictureDecodeLane,
  const std::int32_t* const ptsWords,
  const std::int32_t pictureChangedFlag,
  std::int32_t* const outReferenceSeedWords
)
{
  const std::int32_t frameCount = pictureDecodeLane->decodeOrderMetric;
  const std::int32_t frameRateScale = SFTIM_prate[pictureDecodeLane->frameRateIndex];

  if (workctrl->seekStampHigh < 0) {
    const std::int64_t framePts = sfmpv_Nfrm2Pts(frameCount, frameRateScale);
    std::int64_t ptsBias = (static_cast<std::int64_t>(static_cast<std::uint32_t>(ptsWords[1])) << 32)
      | static_cast<std::uint32_t>(ptsWords[0]);
    ptsBias -= framePts;
    if (ptsBias < 0) {
      ptsBias = 0;
    }
    workctrl->seekStampLow = static_cast<std::int32_t>(ptsBias);
    workctrl->seekStampHigh = static_cast<std::int32_t>(ptsBias >> 32);
  }

  std::int64_t ptsDelta = (static_cast<std::int64_t>(static_cast<std::uint32_t>(ptsWords[1])) << 32)
    | static_cast<std::uint32_t>(ptsWords[0]);
  ptsDelta -= (static_cast<std::int64_t>(static_cast<std::uint32_t>(workctrl->seekStampHigh)) << 32)
    | static_cast<std::uint32_t>(workctrl->seekStampLow);
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
  moho::SfmpvPictureDecodeLane* const pictureDecodeLane,
  char* const delimiterCursor,
  std::int32_t* const outPresentationPtsWords,
  std::int32_t* const outReferenceSeedWords,
  const std::int32_t pictureChangedFlag
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
    workctrl->transferState.transfer.demux.prepSourceLaneIndex,
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
    workctrl,
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const timingLane = &workctrl->timingLane;

  std::int32_t result = static_cast<std::int32_t>(timingLane->concatVideoTimeUnit[0]);
  if (result == 0) {
    moho::SfmpvPackedTimecode headTimecode{};
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
    std::memcpy(&headTimecode, &timingLane->repeatFieldTimecode, sizeof(headTimecode));
    headTimecode.halfFrameCarry = 0;

    std::int32_t headTimeMajor = 0;
    std::int32_t headTimeMinor = 0;
    (void)SFTIM_Tc2Time(&headTimecode, &headTimeMajor, &headTimeMinor);

    timingLane->concatVideoTimeUnit[9] = static_cast<std::uint32_t>(headTimeMajor);
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const timingLane = &workctrl->timingLane;

  moho::SfmpvPackedTimecode decodeTimecode{};
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(&decodeTimecode, &timingLane->repeatFieldTimecode, sizeof(decodeTimecode));

  std::int32_t decodeTimeMajor = 0;
  std::int32_t decodeTimeMinor = 0;
  (void)SFTIM_Tc2Time(&decodeTimecode, &decodeTimeMajor, &decodeTimeMinor);

  auto* const pendingStartTtu = AddressToPointer<moho::SfmpvTtu>(PointerToAddress(&timingLane->pendingStartTtu));
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(pendingStartTtu->packedTimecodeWords, &decodeTimecode, sizeof(decodeTimecode));
  pendingStartTtu->timeMajor = decodeTimeMajor - static_cast<std::int32_t>(timingLane->concatVideoTimeUnit[9]);
  pendingStartTtu->timeMinor = decodeTimeMinor;
  pendingStartTtu->state = 1;

  auto* const decodeTtu = AddressToPointer<moho::SfmpvTtu>(PointerToAddress(&timingLane->concatAudioTimeUnit[0]));
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
  moho::SfmpvPackedTimecode* const outTimecodeLane
)
{
  const auto* const frameObject = AddressToPointer<SfmpvfTimecodeSource>(frameObjectAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTiming>(frameObjectAddress);

  std::int32_t frameTimeMajor = 0;
  std::int32_t frameTimeMinor = 0;
  (void)SFTIM_Tc2Time(frameTiming->frameTtu.packedTimecodeWords, &frameTimeMajor, &frameTimeMinor);

  frameTiming->frameTtu.timeMajor = frameTimeMajor - static_cast<std::int32_t>(workctrl->timingLane.concatVideoTimeUnit[9]);
  frameTiming->frameTtu.timeMinor = frameTimeMinor;
  frameTiming->frameTtu.state = 1;

  if (static_cast<std::int32_t>(workctrl->timingLane.concatAudioTimeUnit[9]) <= frameTiming->frameTtu.timeMajor) {
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
    std::memcpy(
      &workctrl->timingLane.concatAudioTimeUnit[0],
      &frameTiming->frameTtu,
      sizeof(moho::SfmpvTtu)
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  const std::int32_t decoderHandle = mpvInfo->decoderHandle;

  SfmpvDecodeFrameParam decodeFrameParam{};
  std::int32_t frameObjectAddress = 0;
  if (sfmpv_SetFrmPara(workctrlAddress, &mpvInfo->pictureDecodeLane, &decodeFrameParam, &frameObjectAddress) != 0) {
    return 0;
  }

  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
  std::int32_t referenceErrorMajor = 0;
  std::int32_t referenceErrorMinor = 0;
  (void)sfmpv_ReadRefErrCnt(workctrlAddress, mpvInfo, &referenceErrorMajor, &referenceErrorMinor);

  (void)sfmpv_CopyPicUsrInf(
    frameObject->pictureUserInfoAddress,
    PointerToAddress(&mpvInfo->pictureUserBufferMirrorAddress)
  );
  (void)sfmpv_SetStartTtu(workctrlAddress);

  const std::int64_t decodeStart = SFTMR_GetTmr();
  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1);
  const std::int32_t decodeResult = MPV_DecodeFrmSj(decoderHandle, streamBufferAddress, &decodeFrameParam);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1) - flowCountBefore;

  const std::int64_t decodeElapsed = SFTMR_GetTmr() - decodeStart;
  SFTMR_AddTsum(
    &workctrl->timerInfo.summaries[mpvInfo->pictureDecodeLane.pictureType],
    static_cast<std::int32_t>(decodeElapsed),
    static_cast<std::int32_t>(decodeElapsed >> 32)
  );

  workctrl->errorInfo.decodeReferenceErrorMajor += decodeFrameParam.reserved28;
  workctrl->errorInfo.decodeReferenceErrorMinor += decodeFrameParam.reserved2C;

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
    if (workctrl->createTemplate.bufferFormat == 3 && (pictureType == 1 || pictureType == 2)) {
      SFMPVF_RefStbyFrm(frameObjectAddress);
    } else {
      SFMPVF_StbyFrm(frameObjectAddress);
    }

    MPV_GetDctCnt(decoderHandle, &workctrl->playbackInfo.decoderDctCountPrimary, &workctrl->playbackInfo.decoderDctCountSecondary);
    mpvInfo->lateFrameCounter = 0;
  }

  SFPLY_AddDecPic(workctrl, 1, mpvInfo->pictureDecodeLane.pictureType);
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
  const moho::SfmpvPictureDecodeLane* const pictureDecodeLane,
  SfmpvDecodeFrameParam* const decodeFrameParam,
  std::int32_t* const outFrameObjectAddress
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  const std::int32_t pendingFrameObjectAddress = mpvInfo->pendingFrameObjectAddress;
  std::int32_t frameObjectAddress = pendingFrameObjectAddress;
  if (frameObjectAddress == 0) {
    auto* const allocatedFrame = SFMPVF_AllocFrm(workctrlAddress);
    frameObjectAddress = PointerToAddress(allocatedFrame);
    *outFrameObjectAddress = frameObjectAddress;
    if (frameObjectAddress == 0) {
      workctrl->playbackInfo.frameAllocationFailed = 1;
      return -1;
    }
  } else {
    *outFrameObjectAddress = frameObjectAddress;
  }

  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(&frameObject->pictureDecodeLane, pictureDecodeLane, sizeof(moho::SfmpvPictureDecodeLane));
  frameObject->referenceErrorSeedMajor = mpvInfo->referenceErrorSeedMajor;
  frameObject->referenceErrorSeedMinor = mpvInfo->referenceErrorSeedMinor;

  if (workctrl->createTemplate.bufferFormat == 3) {
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
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->primaryReferenceFrameObjectAddress);
    decodeFrameParam->primaryFrameBaseAddress = primaryReferenceFrame->frameSurfaceBaseAddress;

    const std::int32_t heightBlocks32 = (pictureDecodeLane->pictureHeightPixels + 31) / 32;
    const std::int32_t lumaPlaneOffsetBytes = (lumaBlocks32 * heightBlocks32) << 10;
    const std::int32_t primaryLumaAddress = decodeFrameParam->primaryFrameBaseAddress + lumaPlaneOffsetBytes;
    decodeFrameParam->primaryLumaPlaneAddress = primaryLumaAddress;

    const std::int32_t chromaPlaneBytes = (32 * chromaBlocks32) * ((32 * heightBlocks32) / 2);
    decodeFrameParam->primaryChromaPlaneAddress = primaryLumaAddress + chromaPlaneBytes;

    const auto* const secondaryReferenceFrame =
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->secondaryReferenceFrameObjectAddress);
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
  workctrl->playbackInfo.frameAllocationFailed = 0;
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
  const moho::SfmpvInfo* const mpvInfo,
  std::int32_t* const outErrorMajor,
  std::int32_t* const outErrorMinor
)
{
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  if (workctrl->createTemplate.bufferFormat != 3) {
    *outErrorMajor = 0;
    *outErrorMinor = 0;
    return PointerToAddress(outErrorMajor);
  }

  const std::int32_t pictureType = mpvInfo->pictureDecodeLane.pictureType;
  if (pictureType == 2) {
    const auto* const primaryReferenceFrame =
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->primaryReferenceFrameObjectAddress);
    *outErrorMajor = primaryReferenceFrame->referenceErrorMajor;
    *outErrorMinor = primaryReferenceFrame->referenceErrorMinor;
    return mpvInfo->primaryReferenceFrameObjectAddress;
  }

  if (pictureType == 3) {
    const auto* const primaryReferenceFrame =
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->primaryReferenceFrameObjectAddress);
    const auto* const secondaryReferenceFrame =
      AddressToPointer<const moho::SfmpvfFrameObject>(mpvInfo->secondaryReferenceFrameObjectAddress);

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const timingLane = &workctrl->timingLane;

  std::int32_t result = timingLane->interpolationEnabled;
  if (result != 0) {
    return result;
  }

  moho::SfmpvPackedTimecode startTimecode{};
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(&startTimecode, timingLane->pendingStartTtu.packedTimecodeWords, sizeof(startTimecode));

  if (sfmpv_IsDefect(workctrlAddress, 3) == 0 && sfmpv_IsPtypeSkip(workctrlAddress, 3) == 0) {
    startTimecode.halfFrameCarry = 0;
  }

  std::int32_t startTimeMajor = 0;
  std::int32_t startTimeMinor = 0;
  (void)SFTIM_Tc2Time(&startTimecode, &startTimeMajor, &startTimeMinor);

  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTiming>(frameObjectAddress);
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
  std::memcpy(&frameTiming->frameTtu, &workctrl->timingLane.pendingStartTtu, sizeof(moho::SfmpvTtu));
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const frameTiming = AddressToPointer<SfmpvfFrameTiming>(frameObjectAddress);

  std::int32_t result = frameObjectAddress;

  frameTiming->resolvedTimeMinor = frameTiming->frameTtu.timeMinor;
  frameTiming->resolvedTimeMajor =
    frameTiming->frameTtu.timeMajor + workctrl->timerTail.decodeProgressTime - workctrl->timingLane.frameInterpolationTime;
  frameTiming->frameStartTimeMajor = frameTiming->frameTtu.timeMajor;
  frameTiming->frameEndTimeMajor = frameTiming->frameTtu.timeMajor + workctrl->timerTail.decodeProgressTime;

  if (workctrl->timerTail.maxFrameTimeMajor < frameTiming->resolvedTimeMajor) {
    workctrl->timerTail.maxFrameTimeMajor = frameTiming->resolvedTimeMajor;
    result = frameTiming->resolvedTimeMinor;
    workctrl->timerTail.maxFrameTimeMinor = result;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const frameRepeat = AddressToPointer<SfmpvfFrameRepeat>(frameObjectAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  sfmpv_ReadTcode(frameObjectAddress, &workctrl->timingLane.repeatFieldTimecode);

  if (resetHistory != 0) {
    for (std::int32_t index = 0; index < 64; ++index) {
      workctrl->timerTail.repeatFieldHistory.samples[index].repeatFieldCount = -1;
    }
    workctrl->timerTail.repeatFieldHistory.samples[0].accumulatedRepeatCount = -1;
  } else if (frameRepeat->pictureType == 1 || frameRepeat->pictureType == 2) {
    const std::int32_t referenceFrameAddress = mpvInfo->secondaryReferenceFrameObjectAddress;
    const auto* const referenceFrame = AddressToPointer<SfmpvfFrameRepeat>(referenceFrameAddress);

    std::int32_t scanOrdinal = referenceFrame->decodeOrderIndex;
    std::int32_t targetOrdinal = frameRepeat->historyOrdinal;
    if (targetOrdinal < scanOrdinal) {
      targetOrdinal += 1024;
    }

    for (std::int32_t ordinal = scanOrdinal + 1; ordinal < targetOrdinal; ++ordinal) {
      workctrl->timerTail.repeatFieldHistory.samples[Modulo64Index(ordinal)].repeatFieldCount = -1;
    }
  }

  const std::int32_t currentIndex = Modulo64Index(frameRepeat->historyOrdinal);
  moho::SfmpvRepeatFieldSample& currentSample = workctrl->timerTail.repeatFieldHistory.samples[currentIndex];
  currentSample.repeatFieldCount = workctrl->timingLane.repeatFieldTimecode.repeatFieldCount;

  if (resetHistory != 0) {
    currentSample.accumulatedRepeatCount = 0;
  } else if (
    frameRepeat->historyOrdinal != 0
    || workctrl->timerTail.repeatFieldHistory.samples[0].accumulatedRepeatCount != static_cast<std::int16_t>(-1)
  ) {
    std::int32_t misses = 0;
    std::int32_t searchOrdinal = currentIndex + 63;
    while (workctrl->timerTail.repeatFieldHistory.samples[Modulo64Index(searchOrdinal)].repeatFieldCount == static_cast<std::int16_t>(-1)) {
      ++misses;
      --searchOrdinal;
      if (misses >= 64) {
        break;
      }
    }

    if (misses < 64) {
      const moho::SfmpvRepeatFieldSample& previousSample =
        workctrl->timerTail.repeatFieldHistory.samples[Modulo64Index(searchOrdinal)];
      currentSample.accumulatedRepeatCount =
        static_cast<std::int16_t>(previousSample.repeatFieldCount + previousSample.accumulatedRepeatCount);
    }
  } else {
    workctrl->timerTail.repeatFieldHistory.samples[0].accumulatedRepeatCount = 0;
  }

  workctrl->timingLane.repeatFieldTimecode.repeatFieldAccumulated = currentSample.accumulatedRepeatCount;

  if (frameRepeat->pictureType == 3 && currentSample.repeatFieldCount != 0) {
    const std::int32_t referenceFrameAddress = mpvInfo->secondaryReferenceFrameObjectAddress;
    auto* const referenceFrame = AddressToPointer<SfmpvfFrameRepeat>(referenceFrameAddress);

    const std::int32_t referenceIndex = Modulo64Index(referenceFrame->decodeOrderIndex);
    const std::int16_t propagatedRepeat =
      static_cast<std::int16_t>(currentSample.repeatFieldCount + currentSample.accumulatedRepeatCount);
    workctrl->timerTail.repeatFieldHistory.samples[referenceIndex].accumulatedRepeatCount = propagatedRepeat;
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
moho::SfmpvfFrameObject* SFMPVF_AllocFrm(const std::int32_t workctrlAddress)
{
  SFLIB_LockCs();

  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  const std::int32_t frameObjectCount = mpvInfo->frameObjectCount;

  moho::SfmpvfFrameObject* allocatedFrameObject = nullptr;
  for (std::int32_t frameIndex = 0; frameIndex < frameObjectCount; ++frameIndex) {
    moho::SfmpvfFrameObject& frameObject = mpvInfo->frameObjects[frameIndex];
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
      (mpvInfo->persistedPara.nfrmPoolWork * configuredFrameUnitBytes) << 6;
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

    if (availableFrameSlots < mpvInfo->persistedPara.nfrmPoolWork) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameBufferTooSmall);
    }

    mpvInfo->persistedRfbAddressTable[0] = mpvInfo->persistedPara.val4;
    mpvInfo->persistedRfbAddressTable[1] = mpvInfo->persistedPara.val4 + requestedSlotBytes;
    for (std::int32_t slotIndex = 0; slotIndex < availableFrameSlots; ++slotIndex) {
      mpvInfo->persistedSofDecTabs[slotIndex] = mpvInfo->persistedPara.val8 + (slotIndex * requestedSlotBytes);
    }
  } else {
    availableFrameSlots = mpvInfo->persistedPara.nfrmPoolWork;
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

  if (workctrl->createTemplate.bufferFormat == 3) {
    std::int32_t movableFrameCount = availableFrameSlots;
    if (movableFrameCount >= 14) {
      movableFrameCount = 14;
    }

    auto* const mpvFrameInfo = mpvInfo;
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

    auto* const mpvFrameInfo = mpvInfo;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  SfbufRingCursorSnapshot ringCursor{};
  if (SFBUF_RingGetRead(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex, reinterpret_cast<std::int32_t*>(&ringCursor)) != 0) {
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
      AddSigned32ToLane(&workctrl->playbackInfo.flowCounter1.decodedUnits, advanceBytes);
      break;
    }
  }

  AddSigned32ToLane(&workctrl->playbackInfo.flowCounter1.consumedBytes, advanceBytes);
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  return SFBUF_RingAddRead(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex, advanceCount);
}

/**
 * Address: 0x00AD4B30 (FUN_00AD4B30, _sfmpv_UpdateFlowCnt)
 *
 * What it does:
 * Updates per-handle stream-flow counters from current source-lane SJ flow.
 */
std::int32_t sfmpv_UpdateFlowCnt(const std::int32_t workctrlAddress)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  std::int32_t streamHandleAddress = 0;
  (void)SFBUF_RingGetSj(workctrlAddress, workctrl->transferState.transfer.demux.prepSourceLaneIndex, &streamHandleAddress);
  std::int32_t result = streamHandleAddress;
  if (streamHandleAddress != 0) {
    std::int32_t nextFlowLow = 0;
    std::int32_t nextFlowHigh = 0;
    (void)SFBUF_GetFlowCnt(streamHandleAddress, &nextFlowLow, &nextFlowHigh);

    const std::uint64_t mergedFlow = static_cast<std::uint64_t>(
      SFBUF_UpdateFlowCnt(
        FlowWordLow(workctrl->playbackInfo.flowCounter1.sourceFlowBytes),
        FlowWordHigh(workctrl->playbackInfo.flowCounter1.sourceFlowBytes),
        nextFlowLow
      )
    );
    workctrl->playbackInfo.flowCounter1.sourceFlowBytes = mergedFlow;
    result = FlowWordLow(mergedFlow);
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
  const SfmpvPictureAttribute* const /*pictureAttribute*/
)
{
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const auto* const timingLane = &workctrl->timingLane;
  const auto* const concatAudioTtu =
    reinterpret_cast<const moho::SfmpvTtu*>(timingLane->concatAudioTimeUnit);
  if (concatAudioTtu->state == 0) {
    return 0;
  }

  moho::SfmpvPackedTimecode currentTimecode{};
  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  moho::SfmpvPackedTimecode* const outTimecode
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
  const moho::SfmpvPackedTimecode* const sourceTimecode,
  moho::SfmpvPackedTimecode* const outTimecode
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
  SfmpvPictureAttribute* const pictureAttribute,
  const std::int64_t presentationPts,
  const std::int32_t detectErrorMode
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const timingLane = &workctrl->timingLane;
  auto* const reformTimecode = &timingLane->repeatFieldTimecode;
  const auto* const concatAudioTtu =
    reinterpret_cast<const moho::SfmpvTtu*>(timingLane->concatAudioTimeUnit);
  const auto* const concatAudioTimecode =
    reinterpret_cast<const moho::SfmpvPackedTimecode*>(concatAudioTtu->packedTimecodeWords);

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
      workctrl->timerTail.repeatFieldHistory.samples[0].accumulatedRepeatCount = repeatAccumulator;
      workctrl->timerTail.repeatFieldHistory.samples[pictureAttribute->timecodeFrameOrdinal].accumulatedRepeatCount = repeatAccumulator;
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

  if (PointerToAddress(workctrl->seekState.handle) == 0) {
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
  SfmpvPictureAttribute* const pictureAttribute,
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  if (workctrl->movieInfo.frameRateBase != 0) {
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
    &workctrl->movieInfo,
    bitRate,
    AddressToPointer<const std::int32_t>(frameInfoAddress),
    vbvBufferBytes
  );
  return sfmpv_ChkBufSiz(workctrlAddress, reinterpret_cast<const std::int32_t*>(&workctrl->movieInfo));
}

/**
 * Address: 0x00AD3AA0 (FUN_00AD3AA0, _sfmpv_SetMvInf)
 *
 * What it does:
 * Copies decoded frame-dimension words into the per-workctrl MV info lane and
 * latches bitrate/VBV sizing words used by buffer sizing checks.
 */
std::int32_t sfmpv_SetMvInf(
  moho::SfplyMovieInfo* const destinationInfo,
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
  auto* const header = AddressToPointer<SfmpvHeader>(result);
  if (header != nullptr && header->hasHeader == 0) {
    const auto* const headerChunk = AddressToPointer<SfbufRingChunk>(pictureHeaderChunkAddress);

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

    const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  const std::int32_t defectLaneAddress = PointerToAddress(&mpvInfo->pictureDecodeLane);
  const auto* const defectLane = AddressToPointer<moho::SfmpvPictureDecodeLane>(defectLaneAddress);

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
  const auto* const chunk = reinterpret_cast<const SfbufRingChunk*>(chunkWords);

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
  const auto* const defectLane = AddressToPointer<SfmpvDefectLane>(defectLaneAddress);

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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t seekTimeMajor = workctrl->seekState.requestWords[1];
  if (seekTimeMajor < 0) {
    return 0;
  }

  if (workctrl->timingLane.interpolationEnabled != 0) {
    return 0;
  }

  return (
           UTY_CmpTime(
             seekTimeMajor,
             workctrl->seekState.requestWords[2],
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
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
  auto* const destinationInfo = AddressToPointer<SfbufRingChunk>(destinationInfoAddress);
  const auto* const sourceInfo = AddressToPointer<SfbufRingChunk>(sourceInfoAddress);

  // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  switch (pictureType) {
    case 1:
      return (workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionPtype1DecodeEnable] == 0) ? 1 : 0;
    case 2:
      return (workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionPtype2DecodeEnable] == 0) ? 1 : 0;
    case 3:
      return (workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionPtype3DecodeEnable] == 0) ? 1 : 0;
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
  const SfbufRingChunk* const chunkWords
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);

  if (SFSET_GetCond(workctrlAddress, 7) != 0) {
    return nullptr;
  }

  const std::int32_t frameAreaProduct = workctrl->movieInfo.frameAreaWidthPixels * workctrl->movieInfo.frameAreaHeightPixels;
  if (pictureType == 3) {
    auto* const emptyPicture = static_cast<std::uint8_t*>(
      MPV_IsEmptyBpic(reinterpret_cast<const char*>(chunkWords->bufferAddress), chunkWords->byteCount, frameAreaProduct)
    );
    if (emptyPicture != nullptr) {
      ++workctrl->playbackInfo.emptyBpicCount;
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
    ++workctrl->playbackInfo.emptyPpicCount;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const timingLane = &workctrl->timingLane;
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  std::int32_t interpolationTime = 0;
  if (timingLane->interpolationEnabled != 0) {
    interpolationTime = timingLane->pendingStartTtu.timeMajor + workctrl->timerTail.decodeProgressTime - timingLane->frameInterpolationTime;
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

  if (SFTIM_GetSpeed(workctrlAddress) <= 1000 && mpvInfo->lateFrameCounter >= workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionLateFrameGateThreshold]) {
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
  const auto* const workctrl = AddressToPointer<const moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  *outDeltaMinor = workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionFrameDeltaMinor];
  const std::int32_t result = workctrl->conditions[moho::SofdecSfdWorkctrlSubobj::kSfdConditionFrameDeltaMajor];
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  sfmpv_SetSkipTtu(workctrlAddress);
  const std::int32_t flowCountBefore = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1);
  const std::int32_t skipDecodeResult = m2v_SkipFrm(mpvInfo->decoderHandle, streamBufferAddress);
  const std::int32_t consumedBytes = SJRBF_GetFlowCnt(AddressToPointer<moho::SofdecSjRingBufferHandle>(streamBufferAddress), 0, 1) - flowCountBefore;

  const std::int32_t checkedResult =
    sfmpv_ChkMpvErr(workctrlAddress, skipDecodeResult, consumedBytes, kSfmpvErrSkipFrameFailed);
  sfmpv_AddRtotSj(workctrlAddress, consumedBytes);
  if (checkedResult != 0) {
    return checkedResult;
  }

  if (mpvInfo->pictureDecodeLane.skipDecisionLatch == 0) {
    mpvInfo->skipIssuedFlag = 1;
  }

  SFPLY_AddSkipPic(workctrl, 1, mpvInfo->pictureDecodeLane.pictureType);
  return 0;
}

/**
 * Address: 0x00AD4BA0 (FUN_00AD4BA0, _SFMPV_Create)
 *
 * IDA signature:
 * int __cdecl SFMPV_Create(int a1);
 *
 * What it does:
 * The `create` slot of the SFMPV transfer strategy. When the workctrl's video
 * condition is enabled, it anchors the MPV info block inside the workctrl,
 * seeds it from the current global MPV parameters, allocates a decoder handle,
 * routes that handle's errors back through `sfmpv_ErrFn`, forwards three of
 * the workctrl's conditions onto the decoder, and finally re-installs the
 * caller's picture-user buffers when the playback layer is coming back from a
 * reset. With the video condition off the whole thing is skipped and it
 * succeeds silently.
 */
std::int32_t SFMPV_Create(const std::int32_t workctrlAddress)
{
  if (SFSET_GetCond(workctrlAddress, 5) == 0) {
    return 0;
  }

  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = &workctrl->transferState.transfer.demux.m2tsMpvInfo.embeddedMpvInfo;
  workctrl->transferState.transfer.demux.mpvInfoHandle = mpvInfo;

  const std::int32_t initInfoResult = sfmpv_InitInf(workctrlAddress, reinterpret_cast<std::uint32_t*>(mpvInfo));
  if (initInfoResult != 0) {
    return initInfoResult;
  }

  const std::int32_t decoderHandle = MPV_Create();
  if (decoderHandle == 0) {
    return SFLIB_SetErr(0, kSfmpvErrCreateFailed);
  }

  if (MPV_SetErrFunc(decoderHandle, reinterpret_cast<std::int32_t>(&sfmpv_ErrFn), workctrlAddress) != 0) {
    sfmpv_DestroySub(decoderHandle);
    return SFLIB_SetErr(0, kSfmpvErrSetErrFuncFailed);
  }

  MPV_SetCond(decoderHandle, 1, AsMpvConditionCallback(SFSET_GetCond(workctrlAddress, 0)));
  MPV_SetCond(decoderHandle, 2, AsMpvConditionCallback(SFSET_GetCond(workctrlAddress, 1)));
  MPV_SetCond(decoderHandle, 6, AsMpvConditionCallback(workctrl->createTemplate.bufferFormat));

  mpvInfo->decoderHandle = decoderHandle;

  if (SFPLY_GetResetFlg() != 0) {
    sfmpvf_SetPicUsrBuf(workctrlAddress, sfmpv_picusr_pbuf, sfmpv_picusr_bufnum, sfmpv_picusr_buf1siz);
  }
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
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
  SfmpvfFrameInfo** const outFrameInfo,
  std::int32_t* const outFrameId
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t frameObjectAddress = SFMPVF_HoldFrm(workctrlAddress);
  if (frameObjectAddress == 0) {
    *outFrameInfo = nullptr;
    return 0;
  }

  sfmpvf_SearchFrmInf(workctrlAddress, frameObjectAddress, outFrameInfo);
  SfmpvfFrameInfo* const frameInfo = *outFrameInfo;

  workctrl->timerTail.readFrameTimeMajor = frameInfo->presentationTimeMajor;
  workctrl->timerTail.readFrameTimeMinor = frameInfo->presentationTimeMinor;

  if (SFTIM_IsGetFrmTime(workctrlAddress, frameInfo) == 0) {
    *outFrameInfo = nullptr;
    return 0;
  }

  if (workctrl->decodePathMode == 2) {
    const std::int32_t frameId = SFMPVF_IssueFrmId(workctrlAddress);
    auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  SfmpvfFrameInfo** const outFrameInfo
)
{
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
  auto* const vfrmData = AddressToPointer<moho::SfmpvfVfrmData>(SFMPVF_SearchVfrmData(workctrlAddress, frameObjectAddress));
  auto* const frameInfo =
    AddressToPointer<SfmpvfFrameInfo>(PointerToAddress(vfrmData) + static_cast<std::int32_t>(sizeof(moho::SfmpvfVfrmData)));

  *outFrameInfo = frameInfo;
  vfrmData->drawState = 1;
  workctrl->transferState.transfer.demux.mpvInfoHandle->activeFrameObjectAddress = frameObjectAddress;

  frameInfo->pictureWidthPixels = frameObject->pictureDecodeLane.pictureWidthPixels;
  frameInfo->pictureHeightPixels = frameObject->pictureDecodeLane.pictureHeightPixels;
  frameInfo->pictureDetailWord08 = frameObject->pictureDecodeLane.pictureDetailWord08;
  frameInfo->pictureDetailWord0C = frameObject->pictureDecodeLane.pictureDetailWord0C;
  frameInfo->pictureType = frameObject->pictureDecodeLane.pictureType;
  frameInfo->presentationTimeMajor = frameObject->presentationTimeMajor;
  frameInfo->presentationTimeMinor = frameObject->presentationTimeMinor;
  frameInfo->decodeConditionMode = workctrl->createTemplate.bufferFormat;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

  std::int32_t frameObjectAddress = 0;
  moho::SfmpvfVfrmData* vfrmData = nullptr;

  if (workctrl->decodePathMode == 2) {
    frameObjectAddress = SFMPVF_SearchFrmObjFromId(workctrlAddress, frameObjectId);
    if (frameObjectAddress == 0) {
      return SFLIB_SetErr(workctrlAddress, kSfmpvErrFrameObjectMissingById);
    }

    vfrmData = AddressToPointer<moho::SfmpvfVfrmData>(SFMPVF_SearchVfrmData(workctrlAddress, frameObjectAddress));
  } else {
    vfrmData = AddressToPointer<moho::SfmpvfVfrmData>(sfmpvf_GetVfrmDataFromFrmInf(workctrlAddress, frameInfoIndex));
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
  return frameInfoIndex - static_cast<std::int32_t>(sizeof(moho::SfmpvfVfrmData));
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const std::int32_t frameObjectCount = workctrl->transferState.transfer.demux.mpvInfoHandle->frameObjectCount;
  if (frameObjectCount <= 0) {
    return 0;
  }

  for (std::int32_t frameIndex = 0; frameIndex < frameObjectCount; ++frameIndex) {
    const auto* const frameObject = &workctrl->transferState.transfer.demux.mpvInfoHandle->frameObjects[frameIndex];
    if (PointerToAddress(frameObject) == frameObjectAddress) {
      return PointerToAddress(&workctrl->bufferState.vfrmDataLanes[frameIndex]);
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  const auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  auto* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;
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
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  auto* const frameObject = AddressToPointer<moho::SfmpvfFrameObject>(frameObjectAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  workctrl->transferState.transfer.demux.mpvInfoHandle->allowSingleFrameOutput = shouldSort;
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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  moho::SfmpvInfo* const mpvInfo = workctrl->transferState.transfer.demux.mpvInfoHandle;

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
  auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  *outReprocessed = 0;

  const std::int32_t headerAddress = sfmpv_GetHd(workctrlAddress);
  auto* const header = AddressToPointer<SfmpvHeader>(headerAddress);
  if (header != nullptr && header->hasHeader != 0) {
    // Codec blob IO: vendored codec port keeps raw byte copies 1:1.
    std::memcpy(workctrl->timingLane.concatVideoTimeUnit, header->concatTimeSeedWords, sizeof(header->concatTimeSeedWords));

    SfbufRingChunk pictureRange{};
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
  const auto* const workctrl = AddressToPointer<moho::SofdecSfdWorkctrlSubobj>(workctrlAddress);
  std::int32_t headerWorkspaceAddress = PointerToAddress(workctrl->seekState.handle);
  if (headerWorkspaceAddress == 0) {
    return 0;
  }

  if (workctrl->transferState.transfer.demux.mpvInfoHandle->concatAdvanceCount > 0) {
    return 0;
  }

  return headerWorkspaceAddress + 0xAD0;
}

} // extern "C"
