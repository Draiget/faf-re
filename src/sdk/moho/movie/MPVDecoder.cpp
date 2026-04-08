#include "moho/movie/MPVDecoder.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>

namespace moho
{
  struct SofdecSjMemoryHandle;
}

namespace
{
  struct MPVLibWorkState
  {
    std::uint32_t conditionDefaults[16]; // +0x00
    int primaryAddressMaskEnable;        // +0x40
    int secondaryAddressMaskEnable;      // +0x44
    std::int32_t reserved_48;            // +0x48
    int objectTableBaseAddress;          // +0x4C
    int concealStateBaseAddress;         // +0x50
    int objectCount;                     // +0x54
    int alignedWorkBaseAddress;          // +0x58
  };

  static_assert(sizeof(MPVLibWorkState) == 0x5C, "MPVLibWorkState size must be 0x5C");
  static_assert(offsetof(MPVLibWorkState, primaryAddressMaskEnable) == 0x40, "MPVLibWorkState::primaryAddressMaskEnable offset must be 0x40");
  static_assert(offsetof(MPVLibWorkState, secondaryAddressMaskEnable) == 0x44, "MPVLibWorkState::secondaryAddressMaskEnable offset must be 0x44");
  static_assert(offsetof(MPVLibWorkState, objectTableBaseAddress) == 0x4C, "MPVLibWorkState::objectTableBaseAddress offset must be 0x4C");
  static_assert(offsetof(MPVLibWorkState, concealStateBaseAddress) == 0x50, "MPVLibWorkState::concealStateBaseAddress offset must be 0x50");
  static_assert(offsetof(MPVLibWorkState, objectCount) == 0x54, "MPVLibWorkState::objectCount offset must be 0x54");
  static_assert(offsetof(MPVLibWorkState, alignedWorkBaseAddress) == 0x58, "MPVLibWorkState::alignedWorkBaseAddress offset must be 0x58");

  struct MPVObjectSlotView
  {
    std::uint8_t reserved_000[0x188];
    std::uint32_t activeMarker; // +0x188
  };

  static_assert(offsetof(MPVObjectSlotView, activeMarker) == 0x188, "MPVObjectSlotView::activeMarker offset must be 0x188");

  extern "C" {
    extern MPVLibWorkState mpvlib_libwork;
    extern const std::uint32_t mpvlib_cond_dfl[16];
    extern std::uint8_t mpv_clip_0_255_tbl[0x400];
    extern int mpv_clip_0_255_base;

    extern std::uint16_t mpvvlt_mbai_i_0[];
    extern std::uint16_t mpvvlt_mbai_i_1[];
    extern std::uint16_t mpvvlt_mbai_p_0[];
    extern std::uint16_t mpvvlt_mbai_p_1[];
    extern std::uint16_t mpvvlt_mbai_b_0[];
    extern std::uint16_t mpvvlt_mbai_b_1[];
    extern std::uint16_t mpvvlt_p_mbtype[];
    extern std::uint16_t mpvvlt_b_mbtype[];
    extern std::uint16_t mpvvlt_motion_0[];
    extern std::uint16_t mpvvlt_motion_1[];
    extern std::uint16_t mpvvlt_cbp[];
    extern std::uint16_t mpvvlt_y_dcsiz[];
    extern std::uint16_t mpvvlt_c_dcsiz[];
    extern std::uint16_t mpvvlt2_y_dcsiz[];
    extern std::uint16_t mpvvlt2_c_dcsiz[];
    extern std::uint32_t mpvvlt_run_level_0c[];
    extern std::uint32_t mpvvlt_run_level_0b[];
    extern std::uint32_t mpvvlt_run_level_0a[];
    extern std::uint32_t mpvvlt_run_level_1[];
    extern std::uint32_t mpvvlt_run_level_2[];
    extern std::uint32_t mpvvlt_run_level_4[];

    extern const std::uint16_t* mpvvlc_motion_0;
    extern const std::uint16_t* mpvvlc_motion_1;
    extern const std::uint16_t* mpvvlc_mbai_i_0;
    extern const std::uint16_t* mpvvlc_mbai_i_1;
    extern const std::uint16_t* mpvvlc_mbai_p_0;
    extern const std::uint16_t* mpvvlc_mbai_p_1;
    extern const std::uint16_t* mpvvlc_p_mbtype;
    extern const std::uint16_t* mpvvlc_mbai_b_0;
    extern const std::uint16_t* mpvvlc_mbai_b_1;
    extern const std::uint16_t* mpvvlc_b_mbtype;
    extern const std::uint16_t* mpvvlc_cbp;
    extern const std::uint16_t* mpvvlc_y_dcsiz;
    extern const std::uint16_t* mpvvlc_c_dcsiz;
    extern const std::uint16_t* mpvvlc2_y_dcsiz;
    extern const std::uint16_t* mpvvlc2_c_dcsiz;
    extern std::uint32_t* mpvvlc_run_level_0c;
    extern std::uint32_t* mpvvlc_run_level_0b;
    extern std::uint32_t* mpvvlc_run_level_0a;
    extern std::uint32_t* mpvvlc_run_level_1;
    extern std::uint32_t* mpvvlc_run_level_2;
    extern std::uint32_t* mpvvlc_run_level_4;
    extern std::uint32_t* mpvvlc_run_level_8;

    /**
     * Address: 0x00AF7730 (FUN_00AF7730, _mpvvlc_SetVlcRunLevel)
     *
     * What it does:
     * Builds runtime run-level VLC table lanes into caller-provided state
     * storage and returns next free state address.
     */
    int mpvvlc_SetVlcRunLevel(int runLevelStateBase);
    /**
     * Address: 0x00AF77E0 (FUN_00AF77E0, _mpvvlc_SetVlcDcSiz)
     *
     * What it does:
     * Builds runtime DC-size VLC table lanes into state storage and returns the
     * next free state address.
     */
    int mpvvlc_SetVlcDcSiz(int runLevelState);
    /**
     * Address: 0x00AF7820 (FUN_00AF7820, _mpvvlc_SetVlcMotion)
     *
     * What it does:
     * Builds runtime motion VLC table lanes into state storage and returns the
     * next free state address.
     */
    int mpvvlc_SetVlcMotion(int runLevelState);
    int mpvvlc_SetVlcMbType(int runLevelState);

    int MPVVLC_IsVlcSizErr();
    int MPVDEC_CheckVersion(const char* expectedVersion, int decoderStructSize, int decoderAlignment);
    int MPVLIB_CheckHn(int handleAddress);
    int MPV_CheckDelim(const std::uint8_t* bitstreamCursor);
    std::uint8_t* MPV_BsearchDelim(std::uint8_t* bitstreamCursor, unsigned int scanLengthBytes, int delimiterMask);
    std::uint8_t* MPV_SearchDelim(const std::uint8_t* bitstreamCursor, int scanLengthBytes, int delimiterMask);
    int MPV_MoveChunk(moho::movie::MPVSjStream* stream, int lane, int byteCount);
    int UTY_MemsetDword(void* destination, std::uint32_t value, unsigned int dwordCount);
    std::int32_t* UTY_MemcpyDword(void* destination, const void* source, unsigned int dwordCount);
    void DCT_FsriInit();
    int DCT_FsriInitScaleTbl(int scaleTableBaseAddress);
    int DCT_FsriTrans6Blk();
    int DCT_FsriTransCbp();
    int MPVM2V_Create(int handleAddress);
    void MPVM2V_Destroy(int handleAddress);
    int MPVM2V_SetCond(int handleAddress, int conditionIndex, int callbackAddress);
    int MPVM2V_DecodePicAtr(int handleAddress, moho::movie::MPVSjStream* stream);
    int MPVM2V_DecodeFrm(int handleAddress, moho::movie::MPVSjStream* stream, moho::movie::MPVFrameDecodeSession* frameSession);
    moho::SofdecSjMemoryHandle* SJMEM_Create(std::int32_t bufferAddress, std::int32_t bufferSize);
    std::int32_t SJMEM_GetNumData(moho::SofdecSjMemoryHandle* handle, std::int32_t lane);
    void SJMEM_Destroy(moho::SofdecSjMemoryHandle* handle);
    void MPVCMC_InitObj(void* handleAddress);
    int sub_AF7E40(void* dctPlaneStateAddress);
    std::int32_t* MPV_SetUsrSj(int handleAddress, int streamIndex, int streamObject, int streamCallback, int streamContext);
    std::int32_t* MPV_SetPicUsrBuf(int handleAddress, int userBufferAddress, int userContextAddress);
    std::uint8_t mpvhdec_ReadKernelIntraIdcPrec3(moho::movie::MPVDecoderScanContext* decoderContext, void* decodeState);
    std::uint8_t sub_AFAE50(moho::movie::MPVDecoderScanContext* decoderContext, void* decodeState);
    std::uint8_t sub_AFD7C0(moho::movie::MPVDecoderScanContext* decoderContext, void* decodeState);
    void MPVUMC_Finish();
    void MPVM2V_Finish();
    int MPVCONCEAL_Finish(int concealStateBaseAddress, int concealStateSizeBytes);
    int mpvhdec_GetCodec(int handleAddress, moho::movie::MPVSjChunk* chunk);
    int MPVHDEC_RecoverSj(int handleAddress, int expectedDelimiter, moho::movie::MPVSjStream* stream);
    int mpvhdec_GetCurDelim(moho::movie::MPVSjStream* stream);
    int mpvhdec_DecPscSj(int handleAddress, moho::movie::MPVSjStream* stream);
    int mpvhdec_DecGscSj(int handleAddress, moho::movie::MPVSjStream* stream);
    int mpvhdec_DecEscSj(int handleAddress, moho::movie::MPVSjStream* stream);
    int mpvhdec_DecUdscSj(int handleAddress, moho::movie::MPVSjStream* stream);
    int mpvhdec_DecShcSj(int handleAddress, moho::movie::MPVSjStream* stream);
    std::int32_t* mpvhdec_InitIqm(int handleAddress);
    std::int32_t* mpvhdec_InitNqm(int handleAddress);
    int mpvhdec_AnalyUd(std::int32_t* handleWords, std::uint8_t* userDataStart, int chunkSize);
    int mpvhdec_DecSeqUdsc(std::int32_t* handleWords, const std::uint8_t* userDataStart, int consumedByteCount);
    void sub_C0E1B0(moho::movie::MPVDecoderScanContext* decoderContext);
    void sub_C0E2E0(moho::movie::MPVDecoderScanContext* decoderContext);
    void MPVUMC_InitOutRfb(int handleAddress);
    void MPVCMC_InitMcOiRt(int handleAddress);
    void MPVCMC_SetCcnt(int handleAddress);
    void MPVBDEC_StartFrame(int handleAddress);
    int MPVSL_DecPicture(int handleAddress, moho::movie::MPVSjStream* stream);
    void MPVUMC_EndOfFrame(int handleAddress);
    extern const std::uint8_t byte_11081A0[64];
    extern const std::int32_t mpvbdec_dfl_iqm[64];
    int MPVUMCT_Intra(moho::movie::MPVDecoderContextPrefix* context);
    int MPVUMCT_Forward(moho::movie::MPVDecoderContextPrefix* context);
    int MPVUMCT_Backward(moho::movie::MPVDecoderContextPrefix* context);
    int MPVUMCT_BiDirect(moho::movie::MPVDecoderContextPrefix* context);
    int MPVUMCT_PpicSkipped(moho::movie::MPVDecoderContextPrefix* context, int skippedMacroblockCount);
    int MPVUMCT_BpicSkipped(moho::movie::MPVDecoderContextPrefix* context, int skippedMacroblockCount);

    void SJ_SplitChunk(
      moho::movie::MPVSjChunk* sourceChunk, int splitOffset, moho::movie::MPVSjChunk* leftChunk, moho::movie::MPVSjChunk* rightChunk
    );
    int MPV_GoNextDelimSj(moho::movie::MPVSjStream* stream);
  }

  using moho::movie::MPVBitstreamState;
  using moho::movie::MPVDecoderContextPrefix;
  using moho::movie::MPVDecoderScanContext;
  using moho::movie::MPVDecoderRuntimeStats;
  using moho::movie::MPVDecodeReadKernelFn;
  using moho::movie::MPVFrameDecodeSession;
  using moho::movie::MPVInterpolationKernelFn;
  using moho::movie::MPVPredictionVectorSet;
  using moho::movie::MPVPredictionKernelState;
  using moho::movie::MPVSjChunk;
  using moho::movie::MPVSjStream;
  using moho::movie::MPVSpatialDelta;
  using MPVDecodeSliceFn = int(__cdecl*)(MPVDecoderScanContext* context, MPVSjStream* stream);
  using MPVSkipMacroblockFn = int(__cdecl*)(MPVDecoderContextPrefix* context, int skippedMacroblockCount);
  using MPVMacroblockDecodeFn = int(__cdecl*)(MPVDecoderContextPrefix* context);

  struct MPVDctPlaneStateView
  {
    std::uint8_t reserved_00[0x18];
    int primaryDecodeCount;        // +0x18
    int secondaryDecodeCount;      // +0x1C
    std::uint8_t reserved_20[0x2C - 0x20];
    int primaryScratchAddress;     // +0x2C
    int secondaryScratchAddress;   // +0x30
    std::uint8_t reserved_34[0x48 - 0x34];
    int coefficientScratchAddress; // +0x48
  };

  struct MPVUserSjLane
  {
    int streamObjectAddress;   // +0x00
    int streamCallbackAddress; // +0x04
    int streamContextAddress;  // +0x08
  };

  static_assert(sizeof(MPVUserSjLane) == 0xC, "MPVUserSjLane size must be 0xC");

  struct MPVPictureDataRange
  {
    int bufferAddress; // +0x00
    int bufferSize;    // +0x04
  };

  static_assert(sizeof(MPVPictureDataRange) == 0x08, "MPVPictureDataRange size must be 0x08");

  static_assert(sizeof(MPVDctPlaneStateView) == 0x4C, "MPVDctPlaneStateView size must be 0x4C");
  static_assert(offsetof(MPVDctPlaneStateView, primaryDecodeCount) == 0x18, "MPVDctPlaneStateView::primaryDecodeCount offset must be 0x18");
  static_assert(offsetof(MPVDctPlaneStateView, secondaryDecodeCount) == 0x1C, "MPVDctPlaneStateView::secondaryDecodeCount offset must be 0x1C");
  static_assert(offsetof(MPVDctPlaneStateView, primaryScratchAddress) == 0x2C, "MPVDctPlaneStateView::primaryScratchAddress offset must be 0x2C");
  static_assert(offsetof(MPVDctPlaneStateView, secondaryScratchAddress) == 0x30, "MPVDctPlaneStateView::secondaryScratchAddress offset must be 0x30");
  static_assert(
    offsetof(MPVDctPlaneStateView, coefficientScratchAddress) == 0x48,
    "MPVDctPlaneStateView::coefficientScratchAddress offset must be 0x48"
  );

  struct MPVSjStreamVTableView
  {
    std::uint8_t reserved_00[0x18];
    void(__cdecl* requestChunk)(MPVSjStream* stream, int lane, int maxSize, MPVSjChunk* outChunk); // +0x18
    void(__cdecl* submitChunk)(MPVSjStream* stream, int lane, MPVSjChunk* chunk); // +0x1C
    void(__cdecl* releaseChunk)(MPVSjStream* stream, int lane, MPVSjChunk* chunk); // +0x20
  };

  struct MPVSjStreamView
  {
    MPVSjStreamVTableView* vtable;
  };

  struct MPVUserDataSinkVTableView
  {
    std::uint8_t reserved_00[0x18];
    void(__cdecl* requestChunk)(void* sinkObject, int lane, int requestedBytes, MPVSjChunk* outChunk); // +0x18
    std::uint8_t reserved_1C[0x04];
    void(__cdecl* submitChunk)(void* sinkObject, int lane, MPVSjChunk* chunk); // +0x20
  };

  struct MPVUserDataSinkView
  {
    MPVUserDataSinkVTableView* vtable;
  };

  using MPVDctTransformFn = int(__cdecl*)();

  struct MPVPictureAttributes
  {
    std::int32_t headerControlWords[14]; // +0x00
    int pictureCodingType;               // +0x38
    int fullPelForwardVector;            // +0x3C
    int fullPelBackwardVector;           // +0x40
    int concealMotionVectors;            // +0x44
    std::int32_t reserved_48;            // +0x48
    std::int32_t reserved_4C;            // +0x4C
    std::int16_t forwardFCode;           // +0x50
    std::int16_t backwardFCode;          // +0x52
    std::int8_t intraDcPrecision;        // +0x54
    std::int8_t pictureStructure;        // +0x55
    std::int8_t topFieldFirst;           // +0x56
    std::int8_t framePredFrameDct;       // +0x57
    std::int8_t concealmentMotionVector; // +0x58
    std::int8_t qScaleType;              // +0x59
    std::int8_t intraVlcFormat;          // +0x5A
    std::int8_t alternateScan;           // +0x5B
    std::int8_t repeatFirstField;        // +0x5C
    std::int8_t chroma420Type;           // +0x5D
    std::int8_t progressiveFrame;        // +0x5E
    std::int8_t compositeDisplayFlag;    // +0x5F
    std::int8_t vAxis;                   // +0x60
    std::int8_t fieldSequence;           // +0x61
    std::int8_t subCarrier;              // +0x62
    std::int8_t burstAmplitude;          // +0x63
    std::int8_t subCarrierPhase;         // +0x64
    std::uint8_t reserved_65[3];         // +0x65
    std::int32_t extensionFlags;         // +0x68
  };

  static_assert(sizeof(MPVPictureAttributes) == 0x6C, "MPVPictureAttributes size must be 0x6C");
  static_assert(offsetof(MPVPictureAttributes, pictureCodingType) == 0x38, "MPVPictureAttributes::pictureCodingType offset must be 0x38");
  static_assert(offsetof(MPVPictureAttributes, forwardFCode) == 0x50, "MPVPictureAttributes::forwardFCode offset must be 0x50");
  static_assert(offsetof(MPVPictureAttributes, qScaleType) == 0x59, "MPVPictureAttributes::qScaleType offset must be 0x59");
  static_assert(offsetof(MPVPictureAttributes, extensionFlags) == 0x68, "MPVPictureAttributes::extensionFlags offset must be 0x68");

  struct MPVPictureAttributeExportBlock
  {
    MPVPictureAttributes pictureAttributes;
    std::uint8_t reserved_6C_to_7F[0x14];
  };

  static_assert(sizeof(MPVPictureAttributeExportBlock) == 0x80, "MPVPictureAttributeExportBlock size must be 0x80");

  struct MPVHandleInitView
  {
    std::uint8_t reserved_000[0x10];
    int runLevel8Address;          // +0x10
    int runLevel4AddressMinus16;   // +0x14
    int runLevel2AddressMinus32;   // +0x18
    int runLevel1AddressMinus32;   // +0x1C
    int runLevel0aAddress;         // +0x20
    int runLevel0bAddress;         // +0x24
    int runLevel0cAddress;         // +0x28
    int concealLaneAddress1120;    // +0x2C
    int concealLaneAddress1100;    // +0x30
    int concealLaneAddress1160;    // +0x34
    int concealLaneAddress1260;    // +0x38
    int concealLaneAddress1280;    // +0x3C
    int clipBaseAddress;           // +0x40
    std::uint8_t reserved_044[0x78 - 0x44];
    MPVDctPlaneStateView dctPlaneState; // +0x78
    std::uint8_t reserved_0C4[0x110 - 0xC4];
    int clipBaseAddressMirror;     // +0x110
    int scanLutBaseAddress;        // +0x114
    int scanLutAddressD20;         // +0x118
    int scanLutAddressEA0;         // +0x11C
    std::uint8_t reserved_120[0x188 - 0x120];
    int objectSlotState;           // +0x188
    int objectInitStatus;          // +0x18C
    union
    {
      std::int32_t conditionCallbacks[16]; // +0x190
      struct
      {
        std::uint8_t reserved_190_to_1AB[0x1AC - 0x190];
        int serviceReloadInterval; // +0x1AC
      };
    };
    MPVPictureAttributes pictureAttributes; // +0x1D0
    std::uint8_t reserved_23C[0x250 - 0x23C];
    std::uint8_t reserved_250[0x25C - 0x250];
    int recoverEventCounter;      // +0x25C
    int recoverConditionCounter;  // +0x260
    std::uint8_t reserved_264[0x2A4 - 0x264];
    int sequenceAspectRatioCode;    // +0x2A4
    int sequenceBitRateCode;        // +0x2A8
    int sequenceVbvBufferCode;      // +0x2AC
    int constrainedParametersFlag;  // +0x2B0
    int gopClosedFlag;              // +0x2B4
    int gopBrokenLinkFlag;          // +0x2B8
    int pictureVbvDelay;            // +0x2BC
    MPVDecodeSliceFn decodeMacroblockByType;            // +0x2C0
    MPVSkipMacroblockFn decodeSkipRunByType;            // +0x2C4
    MPVMacroblockDecodeFn decodeReadKernelPrimary;      // +0x2C8
    MPVMacroblockDecodeFn decodeReadKernelSecondary;    // +0x2CC
    MPVMacroblockDecodeFn decodeIntraMacroblockByType;  // +0x2D0
    MPVMacroblockDecodeFn decodePredictedMode0;         // +0x2D4
    MPVMacroblockDecodeFn decodePredictedMode1;         // +0x2D8
    MPVMacroblockDecodeFn decodePredictedMode2;         // +0x2DC
    MPVMacroblockDecodeFn decodePredictedMode3;         // +0x2E0
    MPVDctTransformFn dctTransformSixBlocks; // +0x2E4
    MPVDctTransformFn dctTransformCbp;       // +0x2E8
    std::uint8_t reserved_2EC_to_2EF[0x2F0 - 0x2EC];
    int fullPelForwardVector;    // +0x2F0
    int forwardFCodeMinus1;      // +0x2F4
    int forwardFCodeWrapShift;   // +0x2F8
    int forwardFCodeScale;       // +0x2FC
    std::uint8_t reserved_300_to_313[0x314 - 0x300];
    int fullPelBackwardVector;   // +0x314
    int backwardFCodeMinus1;     // +0x318
    int backwardFCodeWrapShift;  // +0x31C
    int backwardFCodeScale;      // +0x320
    std::uint8_t reserved_324_to_35B[0x35C - 0x324];
    int pictureCodecClassification; // +0x35C
    int sequenceStcCodePrimary;     // +0x360
    int sequenceStcCodeSecondary;   // +0x364
    int sequenceStcCodeTertiary;    // +0x368
    int scanScratchAddress4A0;     // +0x36C
    int scanScratchAddress520;     // +0x370
    int scanScratchAddress5A0;     // +0x374
    int scanScratchAddress620;     // +0x378
    int scanScratchAddress3A0;     // +0x37C
    int scanScratchAddress420;     // +0x380
    std::uint8_t reserved_384[0x1320 - 0x384];
    int recoverNeededFlag;         // +0x1320
    int recoverState;              // +0x1324
    MPVSjChunk activeHeaderChunk;  // +0x1328
    int reserved_1330;             // +0x1330
    int sequenceUserDataIdcPrecisionMode; // +0x1334
    MPVDecodeReadKernelFn decodeReadKernelIntra;     // +0x1338
    MPVDecodeReadKernelFn decodeReadKernelPredicted; // +0x133C
    std::uint8_t reserved_1340[0x1344 - 0x1340];
    int serviceCountdown;          // +0x1344
    const std::uint16_t* decodeTablePrimary;   // +0x1348
    const std::uint16_t* decodeTableSecondary; // +0x134C
    int m2vDecoderHandle;          // +0x1350
    int currentHeaderContext;      // +0x1354
    MPVUserSjLane userSjLanes[4];  // +0x1358
    int pictureUserBufferAddress;  // +0x1388
    int pictureUserContextAddress; // +0x138C
    int pictureUserDecodeState;    // +0x1390
    std::uint8_t reserved_1394[0x13A0 - 0x1394];
    int postCreateMarker;          // +0x13A0
    int headerProgressPrimary;     // +0x13A4
    int headerProgressSecondary;   // +0x13A8
    int motionClampCounter;        // +0x13AC
  };

  static_assert(sizeof(MPVHandleInitView) == 0x13B0, "MPVHandleInitView size must be 0x13B0");
  static_assert(offsetof(MPVHandleInitView, clipBaseAddress) == 0x40, "MPVHandleInitView::clipBaseAddress offset must be 0x40");
  static_assert(offsetof(MPVHandleInitView, dctPlaneState) == 0x78, "MPVHandleInitView::dctPlaneState offset must be 0x78");
  static_assert(offsetof(MPVHandleInitView, objectSlotState) == 0x188, "MPVHandleInitView::objectSlotState offset must be 0x188");
  static_assert(offsetof(MPVHandleInitView, conditionCallbacks) == 0x190, "MPVHandleInitView::conditionCallbacks offset must be 0x190");
  static_assert(offsetof(MPVHandleInitView, pictureAttributes) == 0x1D0, "MPVHandleInitView::pictureAttributes offset must be 0x1D0");
  static_assert(offsetof(MPVHandleInitView, recoverEventCounter) == 0x25C, "MPVHandleInitView::recoverEventCounter offset must be 0x25C");
  static_assert(offsetof(MPVHandleInitView, recoverConditionCounter) == 0x260, "MPVHandleInitView::recoverConditionCounter offset must be 0x260");
  static_assert(offsetof(MPVHandleInitView, sequenceAspectRatioCode) == 0x2A4, "MPVHandleInitView::sequenceAspectRatioCode offset must be 0x2A4");
  static_assert(offsetof(MPVHandleInitView, pictureVbvDelay) == 0x2BC, "MPVHandleInitView::pictureVbvDelay offset must be 0x2BC");
  static_assert(offsetof(MPVHandleInitView, decodeMacroblockByType) == 0x2C0, "MPVHandleInitView::decodeMacroblockByType offset must be 0x2C0");
  static_assert(offsetof(MPVHandleInitView, dctTransformSixBlocks) == 0x2E4, "MPVHandleInitView::dctTransformSixBlocks offset must be 0x2E4");
  static_assert(offsetof(MPVHandleInitView, fullPelForwardVector) == 0x2F0, "MPVHandleInitView::fullPelForwardVector offset must be 0x2F0");
  static_assert(offsetof(MPVHandleInitView, fullPelBackwardVector) == 0x314, "MPVHandleInitView::fullPelBackwardVector offset must be 0x314");
  static_assert(
    offsetof(MPVHandleInitView, pictureCodecClassification) == 0x35C,
    "MPVHandleInitView::pictureCodecClassification offset must be 0x35C"
  );
  static_assert(offsetof(MPVHandleInitView, sequenceStcCodePrimary) == 0x360, "MPVHandleInitView::sequenceStcCodePrimary offset must be 0x360");
  static_assert(offsetof(MPVHandleInitView, sequenceStcCodeTertiary) == 0x368, "MPVHandleInitView::sequenceStcCodeTertiary offset must be 0x368");
  static_assert(offsetof(MPVHandleInitView, recoverNeededFlag) == 0x1320, "MPVHandleInitView::recoverNeededFlag offset must be 0x1320");
  static_assert(offsetof(MPVHandleInitView, activeHeaderChunk) == 0x1328, "MPVHandleInitView::activeHeaderChunk offset must be 0x1328");
  static_assert(
    offsetof(MPVHandleInitView, sequenceUserDataIdcPrecisionMode) == 0x1334,
    "MPVHandleInitView::sequenceUserDataIdcPrecisionMode offset must be 0x1334"
  );
  static_assert(offsetof(MPVHandleInitView, decodeReadKernelIntra) == 0x1338, "MPVHandleInitView::decodeReadKernelIntra offset must be 0x1338");
  static_assert(offsetof(MPVHandleInitView, decodeTablePrimary) == 0x1348, "MPVHandleInitView::decodeTablePrimary offset must be 0x1348");
  static_assert(offsetof(MPVHandleInitView, m2vDecoderHandle) == 0x1350, "MPVHandleInitView::m2vDecoderHandle offset must be 0x1350");
  static_assert(offsetof(MPVHandleInitView, currentHeaderContext) == 0x1354, "MPVHandleInitView::currentHeaderContext offset must be 0x1354");
  static_assert(offsetof(MPVHandleInitView, userSjLanes) == 0x1358, "MPVHandleInitView::userSjLanes offset must be 0x1358");
  static_assert(offsetof(MPVHandleInitView, pictureUserBufferAddress) == 0x1388, "MPVHandleInitView::pictureUserBufferAddress offset must be 0x1388");
  static_assert(offsetof(MPVHandleInitView, pictureUserContextAddress) == 0x138C, "MPVHandleInitView::pictureUserContextAddress offset must be 0x138C");
  static_assert(offsetof(MPVHandleInitView, pictureUserDecodeState) == 0x1390, "MPVHandleInitView::pictureUserDecodeState offset must be 0x1390");
  static_assert(offsetof(MPVHandleInitView, postCreateMarker) == 0x13A0, "MPVHandleInitView::postCreateMarker offset must be 0x13A0");
  static_assert(offsetof(MPVHandleInitView, headerProgressPrimary) == 0x13A4, "MPVHandleInitView::headerProgressPrimary offset must be 0x13A4");
  static_assert(offsetof(MPVHandleInitView, motionClampCounter) == 0x13AC, "MPVHandleInitView::motionClampCounter offset must be 0x13AC");

  MPVInterpolationKernelFn g_mpvInterpolationDispatch[8]{};
  bool g_mpvInterpolationDispatchInitialized = false;

  inline std::uint8_t* AddressToMutablePointer(const int address)
  {
    return reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  inline MPVHandleInitView* AsHandleView(const int address)
  {
    return reinterpret_cast<MPVHandleInitView*>(AddressToMutablePointer(address));
  }

  inline const std::uint8_t* AddressToPointer(const int address)
  {
    return reinterpret_cast<const std::uint8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
  }

  inline std::uint8_t ReadAddressedSample(const int baseAddress, const int sampleOffset)
  {
    return *AddressToPointer(baseAddress + sampleOffset);
  }

  inline int PointerToAddress(const void* pointer)
  {
    return static_cast<int>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(pointer)));
  }

  inline void CopyDwordsToAddress(const int destinationAddress, const void* source, const std::size_t dwordCount)
  {
    std::memcpy(AddressToMutablePointer(destinationAddress), source, dwordCount * sizeof(std::uint32_t));
  }

  inline MPVSjStreamView* AsSjStreamView(MPVSjStream* stream)
  {
    return reinterpret_cast<MPVSjStreamView*>(stream);
  }

  inline MPVUserDataSinkView* AsUserDataSinkView(const int sinkObjectAddress)
  {
    return reinterpret_cast<MPVUserDataSinkView*>(AddressToMutablePointer(sinkObjectAddress));
  }

  inline void SjRequestChunk(MPVSjStream* stream, MPVSjChunk& outChunk)
  {
    AsSjStreamView(stream)->vtable->requestChunk(stream, 1, 0x7FFFFFFF, &outChunk);
  }

  inline void SjSubmitTailChunk(MPVSjStream* stream, MPVSjChunk& tailChunk)
  {
    AsSjStreamView(stream)->vtable->submitChunk(stream, 1, &tailChunk);
  }

  inline void SjReleaseHeadChunk(MPVSjStream* stream, MPVSjChunk& headChunk)
  {
    AsSjStreamView(stream)->vtable->releaseChunk(stream, 0, &headChunk);
  }

  inline void UserDataSinkRequestChunk(const int sinkObjectAddress, const int requestedBytes, MPVSjChunk& outChunk)
  {
    MPVUserDataSinkView* const sink = AsUserDataSinkView(sinkObjectAddress);
    sink->vtable->requestChunk(sink, 0, requestedBytes, &outChunk);
  }

  inline void UserDataSinkSubmitChunk(const int sinkObjectAddress, MPVSjChunk& chunk)
  {
    MPVUserDataSinkView* const sink = AsUserDataSinkView(sinkObjectAddress);
    sink->vtable->submitChunk(sink, 1, &chunk);
  }

  inline std::uint32_t ReadBigEndianWord(const std::uint8_t* cursor)
  {
    return
      (static_cast<std::uint32_t>(cursor[0]) << 24) | (static_cast<std::uint32_t>(cursor[1]) << 16) |
      (static_cast<std::uint32_t>(cursor[2]) << 8) | static_cast<std::uint32_t>(cursor[3]);
  }

  inline std::uint32_t PeekWindowBits(const MPVBitstreamState& bitstreamState, const int topBitShift)
  {
    std::uint32_t value = bitstreamState.bitWindowPrimary >> topBitShift;
    if (bitstreamState.bitCount > topBitShift) {
      value |= bitstreamState.bitWindowSecondary >> ((topBitShift + 32) - bitstreamState.bitCount);
    }
    return value;
  }

  inline void LoadBitstreamFromChunk(const MPVSjChunk& chunk, const int bitAlignment, MPVBitstreamState& bitstreamState)
  {
    std::uint8_t* alignedData =
      reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(chunk.data) & static_cast<std::uintptr_t>(0xFFFFFFFCu));
    const int byteOffset = static_cast<int>(reinterpret_cast<std::uintptr_t>(chunk.data) - reinterpret_cast<std::uintptr_t>(alignedData));
    const int chunkBitOffset = byteOffset * 8;
    int bitCount = bitAlignment + chunkBitOffset;

    std::uint32_t bitWindowPrimary = ReadBigEndianWord(alignedData) << chunkBitOffset;
    std::uint32_t bitWindowSecondary = ReadBigEndianWord(alignedData + 4);
    std::uint8_t* byteCursor = alignedData + 8;

    if (bitCount < 32) {
      bitWindowPrimary <<= bitAlignment;
    } else {
      bitCount -= 32;
      bitWindowPrimary = bitWindowSecondary << bitCount;
      bitWindowSecondary = ReadBigEndianWord(byteCursor);
      byteCursor += 4;
    }

    bitstreamState.bitWindowPrimary = bitWindowPrimary;
    bitstreamState.bitWindowSecondary = bitWindowSecondary;
    bitstreamState.bitCount = bitCount;
    bitstreamState.byteCursor = byteCursor;
  }

  inline int ComputeBitstreamSplitOffset(const MPVBitstreamState& bitstreamState, const std::uint8_t* chunkBase, const bool discardPartialBits)
  {
    const int bitRemainder = discardPartialBits ? (bitstreamState.bitCount & 7) : 0;
    const int roundedBitCount = (bitstreamState.bitCount - bitRemainder + 7) >> 3;
    return static_cast<int>(
      reinterpret_cast<std::intptr_t>(bitstreamState.byteCursor + roundedBitCount) - reinterpret_cast<std::intptr_t>(chunkBase) - 8
    );
  }

  inline void ConsumeBits(
    std::uint32_t& bitWindowPrimary, std::uint32_t& bitWindowSecondary, int& bitCount, std::uint8_t*& byteCursor, const int consumeCount
  )
  {
    bitCount += consumeCount;
    if (bitCount < 32) {
      bitWindowPrimary <<= consumeCount;
      return;
    }

    bitCount -= 32;
    bitWindowPrimary = bitWindowSecondary << bitCount;
    bitWindowSecondary = ReadBigEndianWord(byteCursor);
    byteCursor += 4;
  }

  inline std::uint32_t ConsumeAndExtractBits(
    std::uint32_t& bitWindowPrimary, std::uint32_t& bitWindowSecondary, int& bitCount, std::uint8_t*& byteCursor, const int bitWidth
  )
  {
    const int highShift = 32 - bitWidth;
    if (bitCount < highShift) {
      bitCount += bitWidth;
      const std::uint32_t extracted = bitWindowPrimary >> highShift;
      bitWindowPrimary <<= bitWidth;
      return extracted;
    }

    bitCount = bitCount + bitWidth - 32;
    std::uint32_t extracted = 0;
    if (bitCount != 0) {
      extracted = (bitWindowPrimary | (bitWindowSecondary >> (bitWidth - bitCount))) >> highShift;
      bitWindowSecondary <<= bitCount;
    } else {
      extracted = bitWindowPrimary >> highShift;
    }

    bitWindowPrimary = bitWindowSecondary;
    bitWindowSecondary = ReadBigEndianWord(byteCursor);
    byteCursor += 4;
    return extracted;
  }

  inline std::uint32_t ConsumeHeaderBits(MPVBitstreamState& bitstreamState, const int bitWidth)
  {
    return ConsumeAndExtractBits(
      bitstreamState.bitWindowPrimary,
      bitstreamState.bitWindowSecondary,
      bitstreamState.bitCount,
      bitstreamState.byteCursor,
      bitWidth
    );
  }

  inline bool ConsumeHeaderFlag(MPVBitstreamState& bitstreamState)
  {
    return ConsumeHeaderBits(bitstreamState, 1) != 0;
  }

  inline void CommitHeaderChunkSplit(MPVHandleInitView* handle, MPVSjStream* stream, const int splitOffset)
  {
    MPVSjChunk tailChunk{};
    SJ_SplitChunk(&handle->activeHeaderChunk, splitOffset, &handle->activeHeaderChunk, &tailChunk);
    SjReleaseHeadChunk(stream, handle->activeHeaderChunk);
    SjSubmitTailChunk(stream, tailChunk);
  }

  inline void LoadHeaderChunkBitstream(MPVHandleInitView* handle, MPVSjStream* stream, MPVBitstreamState& bitstreamState)
  {
    SjRequestChunk(stream, handle->activeHeaderChunk);
    LoadBitstreamFromChunk(handle->activeHeaderChunk, 0, bitstreamState);
  }

  inline int ComputeHeaderChunkSplitOffset(const MPVHandleInitView* handle, const MPVBitstreamState& bitstreamState)
  {
    return ComputeBitstreamSplitOffset(bitstreamState, handle->activeHeaderChunk.data, false);
  }

  inline void LoadQuantizationMatrix(MPVBitstreamState& bitstreamState, std::uint8_t* matrixStorage)
  {
    for (int index = 0; index < 64; ++index) {
      matrixStorage[byte_11081A0[index]] = static_cast<std::uint8_t>(ConsumeHeaderBits(bitstreamState, 8));
    }
  }

  constexpr int kMpvStartCodeByteCount = 4;

  inline MPVDecoderRuntimeStats* AsRuntimeStats(MPVDecoderContextPrefix* context)
  {
    return reinterpret_cast<MPVDecoderRuntimeStats*>(context);
  }

  inline MPVPredictionKernelState* AsPredictionKernelState(MPVDecoderContextPrefix* context)
  {
    return &context->predictionKernelState;
  }

  template <typename RowWriter>
  inline void WriteEightRows(moho::movie::MPVBlockWriteTarget& target, RowWriter&& rowWriter)
  {
    std::uint8_t* dst = target.pixels;
    for (int row = 0; row < 8; ++row) {
      rowWriter(dst);
      dst += target.stride;
    }
  }

  inline void ConfigureCopyTargetPlanes(MPVDecoderContextPrefix* context, const MPVSpatialDelta& delta)
  {
    context->copyTargets.blocks[0].pixels = AddressToMutablePointer(delta.luma + context->planeBase0);
    context->copyTargets.blocks[1].pixels = AddressToMutablePointer(delta.luma + context->planeBase1);

    const int plane2Start = delta.chroma + context->planeBase2;
    context->copyTargets.blocks[2].pixels = AddressToMutablePointer(plane2Start);
    context->copyTargets.blocks[3].pixels = AddressToMutablePointer(plane2Start + 8);

    const int lowerPlane2Start = plane2Start + 8 * static_cast<int>(context->planeBase2Stride);
    context->copyTargets.blocks[4].pixels = AddressToMutablePointer(lowerPlane2Start);
    context->copyTargets.blocks[5].pixels = AddressToMutablePointer(lowerPlane2Start + 8);
  }

  template <typename PixelOp>
  inline int RunKernelFromPrimarySource(MPVPredictionKernelState* kernelState, PixelOp&& pixelOp)
  {
    std::uint8_t* destination = AddressToMutablePointer(kernelState->destinationBlockBase);
    const std::uint8_t* source = AddressToPointer(kernelState->sourcePrimary);

    for (int row = 0; row < 8; ++row) {
      for (int column = 0; column < 8; ++column) {
        destination[column] = static_cast<std::uint8_t>(pixelOp(source, column));
      }

      destination += 8;
      source += kernelState->destinationStride;
    }

    return PointerToAddress(source);
  }

  template <typename PixelOp>
  inline int RunKernelFromPrimarySecondarySources(MPVPredictionKernelState* kernelState, PixelOp&& pixelOp)
  {
    std::uint8_t* destination = AddressToMutablePointer(kernelState->destinationBlockBase);
    const std::uint8_t* sourcePrimary = AddressToPointer(kernelState->sourcePrimary);
    const std::uint8_t* sourceSecondary = AddressToPointer(kernelState->sourceSecondary);

    for (int row = 0; row < 8; ++row) {
      for (int column = 0; column < 8; ++column) {
        destination[column] = static_cast<std::uint8_t>(pixelOp(sourcePrimary, sourceSecondary, column));
      }

      destination += 8;
      sourcePrimary += kernelState->destinationStride;
      sourceSecondary += kernelState->destinationStride;
    }

    return PointerToAddress(sourcePrimary);
  }

  template <std::size_t BlockCount>
  inline void ClearScanScratchBlocks(MPVDecoderScanContext* context)
  {
    static_assert(BlockCount <= 6, "BlockCount must not exceed the six MPEG scan scratch blocks");
    std::memset(context->scanScratch0, 0, BlockCount * sizeof(context->scanScratch0));
  }

  template <std::size_t SlotIndex>
  inline std::uint8_t ProbeScanSlot(MPVDecoderScanContext* context, const MPVDecodeReadKernelFn readKernel)
  {
    static_assert(SlotIndex < 6, "SlotIndex must be between 0 and 5");
    context->decodeWorkBase = PointerToAddress(context->scanScratch0 + SlotIndex * sizeof(context->scanScratch0));
    return readKernel(context, &context->decodeBitstreamWord);
  }

  inline std::uint8_t ProbeScanSlot(
    MPVDecoderScanContext* context, const MPVDecodeReadKernelFn readKernel, const std::uint8_t* scanScratchBase
  )
  {
    context->decodeWorkBase = PointerToAddress(scanScratchBase);
    return readKernel(context, &context->decodeBitstreamWord);
  }

  inline void InitializeMpvInterpolationDispatch()
  {
    if (g_mpvInterpolationDispatchInitialized) {
      return;
    }

    // AF6040 C fallback table: no SIMD probe helper is recovered yet in sdk source.
    g_mpvInterpolationDispatch[0] = &moho::movie::MPVKernel_Copy8x8;
    g_mpvInterpolationDispatch[1] = &moho::movie::MPVKernel_AvgHorizontal;
    g_mpvInterpolationDispatch[2] = &moho::movie::MPVKernel_AvgPrimarySecondary;
    g_mpvInterpolationDispatch[3] = &moho::movie::MPVKernel_AvgHorizontalAndSecondary;
    g_mpvInterpolationDispatch[4] = &moho::movie::MPVKernel_Copy8x8;
    g_mpvInterpolationDispatch[5] = &moho::movie::MPVKernel_AvgHorizontal;
    g_mpvInterpolationDispatch[6] = &moho::movie::MPVKernel_AvgPrimarySecondary;
    g_mpvInterpolationDispatch[7] = &moho::movie::MPVKernel_AvgPrimarySecondary;

    g_mpvInterpolationDispatchInitialized = true;
  }
} // namespace

extern "C" std::uint32_t mpvvlt_run_level_8[128]{};
extern "C" int mpvlib_deb_hn_last = 0;
extern "C" MPVDecodeSliceFn dec_mbs_func[4]{};
extern "C" MPVSkipMacroblockFn skip_func[10]{};
extern "C" MPVMacroblockDecodeFn s_mc_intra_func[20]{};
extern "C" MPVMacroblockDecodeFn s_mc_forward_func[10]{};
extern "C" MPVMacroblockDecodeFn s_mc_backward_func[10]{};
extern "C" MPVMacroblockDecodeFn s_mc_bidirect_func[10]{};
extern "C" MPVSkipMacroblockFn thumbnail_skip_func[10]{};
extern "C" MPVMacroblockDecodeFn thumbnail_mc_intra_func[20]{};
extern "C" MPVMacroblockDecodeFn thumbnail_mc_forward_func[10]{};
extern "C" MPVMacroblockDecodeFn thumbnail_mc_backward_func[10]{};
extern "C" MPVMacroblockDecodeFn thumbnail_mc_bidirect_func[10]{};
extern "C" void mpvlib_NoOpInitializeRange(void* stateBaseAddress, int stateSizeBytes);
extern "C" int mpvlib_DefaultConditionNoOp();
extern "C" int mpvlib_InitDctPa(int handleAddress);
extern "C" int mpvlib_SetCondAll(int conditionIndex, int callbackAddress);

namespace
{
  constexpr int kMpvAddressSegmentMask = 0x02000000;
  constexpr std::uint32_t kMpvAddressWindowLowMask = 0x0FFFFFFFu;
  constexpr std::uint32_t kMpvAddressWindowHighBit = 0x80000000u;
  constexpr int kMpvWorkAlignBytes = 0x20;
  constexpr int kMpvObjectStrideBytes = 0x13C0;
  constexpr int kMpvConcealStateOffset = 0x3A0;
  constexpr int kMpvConcealStateSizeBytes = 0x1C60;
  constexpr int kMpvHandleSizeBytes = 0x13B0;
  constexpr int kMpvDctScaleTableOffset = 0x1160;
  constexpr int kMpvClipTableBaseOffset = 0x180;
  constexpr unsigned int kMpvClipTableDwordCount = 0x100;
  constexpr unsigned int kMpvConditionCallbackDwordCount = 0x10;
  constexpr int kMpvHandleSlotStateFree = 1;
  constexpr int kMpvHandleSlotStateAllocated = 2;
  constexpr int kMpvConditionIndexConcealDefault = 8;
  constexpr int kMpvErrInvalidDestroyHandle = -16580095;
  constexpr int kMpvErrInvalidSetCondHandle = -16580094;
  constexpr int kMpvErrInvalidGetCondHandle = -16580080;
  constexpr int kMpvErrInvalidDecodePicAtrHandle = -16580084;
  constexpr int kMpvErrInvalidDecodeFrameHandle = -16580087;
  constexpr int kMpvErrInvalidSetErrFuncHandle = -16580093;
  constexpr int kMpvErrInvalidGetErrInfoHandle = -16580092;
  constexpr int kMpvErrorInfoOffset = 0x250;
  constexpr const char kExpectedMpvDecoderVersion[] = "1.958";

  struct MPVErrorInfoRuntime
  {
    int callbackAddress = 0; // +0x00
    int callbackContext = 0; // +0x04
    int errorCode = 0;       // +0x08
    int reserved0C = 0;      // +0x0C
    int reserved10 = 0;      // +0x10
  };

  static_assert(sizeof(MPVErrorInfoRuntime) == 0x14, "MPVErrorInfoRuntime size must be 0x14");
  static_assert(offsetof(MPVErrorInfoRuntime, callbackAddress) == 0x0, "MPVErrorInfoRuntime::callbackAddress offset must be 0x0");
  static_assert(offsetof(MPVErrorInfoRuntime, callbackContext) == 0x4, "MPVErrorInfoRuntime::callbackContext offset must be 0x4");
  static_assert(offsetof(MPVErrorInfoRuntime, errorCode) == 0x8, "MPVErrorInfoRuntime::errorCode offset must be 0x8");

  MPVErrorInfoRuntime mpverrinf{};

  [[nodiscard]] inline MPVErrorInfoRuntime* ResolveHandleErrorInfo(const int handleAddress)
  {
    return reinterpret_cast<MPVErrorInfoRuntime*>(AddressToMutablePointer(handleAddress + kMpvErrorInfoOffset));
  }

  inline std::uint8_t* AsMutableTableBytes(std::uint16_t* table)
  {
    return reinterpret_cast<std::uint8_t*>(table);
  }

  inline void WriteTableDword(std::uint16_t* table, const std::size_t dwordIndex, const std::uint32_t value)
  {
    std::memcpy(AsMutableTableBytes(table) + dwordIndex * sizeof(std::uint32_t), &value, sizeof(value));
  }

  inline void FillTableDwords(
    std::uint16_t* table, const std::size_t startDwordIndex, const std::size_t dwordCount, const std::uint32_t value
  )
  {
    for (std::size_t i = 0; i < dwordCount; ++i) {
      WriteTableDword(table, startDwordIndex + i, value);
    }
  }

  inline void WriteTableWord(std::uint16_t* table, const std::size_t byteOffset, const std::uint16_t value)
  {
    std::memcpy(AsMutableTableBytes(table) + byteOffset, &value, sizeof(value));
  }

  inline void WriteTableByte(std::uint16_t* table, const std::size_t byteOffset, const std::uint8_t value)
  {
    AsMutableTableBytes(table)[byteOffset] = value;
  }

  inline void FillTableWords(
    std::uint16_t* table, const std::size_t startWordIndex, const std::size_t wordCount, const std::uint16_t value
  )
  {
    std::fill_n(table + startWordIndex, wordCount, value);
  }

  inline void FillDwords(
    std::uint32_t* table, const std::size_t startDwordIndex, const std::size_t dwordCount, const std::uint32_t value
  )
  {
    std::fill_n(table + startDwordIndex, dwordCount, value);
  }

  inline int SignedRoundUpShift(const int value, const int shift)
  {
    const int mask = (1 << shift) - 1;
    const int biased = value + mask;
    return (biased + ((biased >> 31) & mask)) >> shift;
  }

  inline std::uint16_t EncodeVlcWord(const int magnitude, const int suffix)
  {
    return static_cast<std::uint16_t>((magnitude << 4) | suffix);
  }

  inline std::uint16_t EncodeSignedMotionWord(const int magnitude, const std::uint8_t prefix)
  {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(prefix) << 8) | static_cast<std::uint8_t>(magnitude));
  }

  void FillRunLevelVlcRange(const std::size_t startIndex, const std::size_t count, const std::uint32_t value)
  {
    std::fill_n(mpvvlt_run_level_8 + startIndex, count, value);
  }
}

/**
 * Address: 0x00AEAE70 (FUN_00AEAE70, _MPVERR_InitErrInf)
 *
 * What it does:
 * Clears one 0x14-byte MPV error-info lane.
 */
extern "C" void MPVERR_InitErrInf(void* const errorInfoAddress)
{
  auto* const errorInfo = static_cast<MPVErrorInfoRuntime*>(errorInfoAddress);
  errorInfo->callbackAddress = 0;
  errorInfo->callbackContext = 0;
  errorInfo->errorCode = 0;
  errorInfo->reserved0C = 0;
  errorInfo->reserved10 = 0;
}

/**
 * Address: 0x00AEAE60 (FUN_00AEAE60, _MPVERR_Init)
 *
 * What it does:
 * Resets the process-global MPV error-info lane and returns that lane.
 */
extern "C" void* MPVERR_Init()
{
  MPVERR_InitErrInf(&mpverrinf);
  return &mpverrinf;
}

/**
 * Address: 0x00AEAF10 (FUN_00AEAF10, _MPVERR_SetCode)
 *
 * What it does:
 * Routes an MPV error code into either one handle-local or the global error
 * lane and returns the same code.
 */
extern "C" int MPVERR_SetCode(int errorContext, int errorCode);

/**
 * Address: 0x00AEAE90 (FUN_00AEAE90, _MPV_SetErrFunc)
 *
 * What it does:
 * Stores one per-handle error callback address/context pair.
 */
extern "C" int MPV_SetErrFunc(
  const int handleAddress,
  const int errorCallbackAddress,
  const int errorCallbackContext
)
{
  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidSetErrFuncHandle);
  }

  MPVErrorInfoRuntime* const errorInfo = ResolveHandleErrorInfo(handleAddress);
  errorInfo->callbackAddress = errorCallbackAddress;
  errorInfo->callbackContext = errorCallbackContext;
  return 0;
}

/**
 * Address: 0x00AEAED0 (FUN_00AEAED0, _MPV_GetErrInf)
 *
 * What it does:
 * Copies one per-handle 0x14-byte error-info lane into caller storage.
 */
extern "C" int MPV_GetErrInf(const int handleAddress, void* const outErrorInfoAddress)
{
  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidGetErrInfoHandle);
  }

  std::memcpy(outErrorInfoAddress, ResolveHandleErrorInfo(handleAddress), sizeof(MPVErrorInfoRuntime));
  return 0;
}

/**
 * Address: 0x00AEAF50 (FUN_00AEAF50, _mpverr_SetCodeSub)
 *
 * What it does:
 * Stores one error code and, when non-zero and callback is set, dispatches the
 * callback with `(context, errorCode)`.
 */
extern "C" void mpverr_SetCodeSub(void* const errorInfoAddress, const int errorCode)
{
  auto* const errorInfo = static_cast<MPVErrorInfoRuntime*>(errorInfoAddress);
  errorInfo->errorCode = errorCode;
  if (errorCode != 0 && errorInfo->callbackAddress != 0) {
    using ErrorCallbackFn = void(__cdecl*)(int callbackContext, int callbackCode);
    auto* const callback = reinterpret_cast<ErrorCallbackFn>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(errorInfo->callbackAddress))
    );
    callback(errorInfo->callbackContext, errorCode);
  }
}

/**
 * Address: 0x00AEAF10 (FUN_00AEAF10, _MPVERR_SetCode)
 *
 * What it does:
 * Routes an MPV error code into either one handle-local or the global error
 * lane and returns the same code.
 */
extern "C" int MPVERR_SetCode(const int errorContext, const int errorCode)
{
  if (errorContext != 0) {
    mpverr_SetCodeSub(ResolveHandleErrorInfo(errorContext), errorCode);
  } else {
    mpverr_SetCodeSub(&mpverrinf, errorCode);
  }
  return errorCode;
}

/**
 * Address: 0x00AE79E0 (FUN_00AE79E0, _mpvlib_ChkFatal)
 *
 * What it does:
 * Validates MPV decode setup preconditions (VLC table footprint and decoder
 * version signature), then maps failures to MPVERR codes.
 */
extern "C" int mpvlib_ChkFatal()
{
  if (MPVVLC_IsVlcSizErr() != 0) {
    return MPVERR_SetCode(0, -16515325);
  }
  if (MPVDEC_CheckVersion(kExpectedMpvDecoderVersion, 5040, 128) != 0) {
    return MPVERR_SetCode(0, -16515321);
  }
  return 0;
}

/**
 * Address: 0x00AE7A30 (FUN_00AE7A30, _mpvlib_ChkCacheMode)
 *
 * What it does:
 * Cache-mode hook lane retained as a no-op in this binary.
 */
extern "C" void mpvlib_ChkCacheMode()
{
}

/**
 * Address: 0x00AE7A40 (FUN_00AE7A40, _MPVLIB_ConvWorkAddr)
 *
 * What it does:
 * Returns work-memory base address unchanged.
 */
extern "C" int MPVLIB_ConvWorkAddr(const int workAddress)
{
  return workAddress;
}

/**
 * Address: 0x00AE7A50 (FUN_00AE7A50)
 *
 * What it does:
 * Applies the MPV library primary address-mask policy (OR 0x02000000 when
 * enabled by runtime work state).
 */
extern "C" int MPVLIB_ConvAddrPrimary(const int address)
{
  if (mpvlib_libwork.primaryAddressMaskEnable != 0) {
    return address | kMpvAddressSegmentMask;
  }
  return address;
}

/**
 * Address: 0x00AE7A70 (FUN_00AE7A70)
 *
 * What it does:
 * Applies the MPV library secondary address-mask policy (OR 0x02000000 when
 * enabled by runtime work state).
 */
extern "C" int MPVLIB_ConvAddrSecondary(const int address)
{
  if (mpvlib_libwork.secondaryAddressMaskEnable != 0) {
    return address | kMpvAddressSegmentMask;
  }
  return address;
}

/**
 * Address: 0x00AE7A90 (FUN_00AE7A90)
 *
 * What it does:
 * Re-encodes a pointer into MPV window-8 form by preserving low 28 bits and
 * forcing the high bit.
 */
extern "C" std::uint32_t MPVLIB_ConvAddrWindow8(const int address)
{
  return (static_cast<std::uint32_t>(address) & kMpvAddressWindowLowMask) | kMpvAddressWindowHighBit;
}

/**
 * Address: 0x00AE7AA0 (FUN_00AE7AA0, _mpvlib_InitClip)
 *
 * What it does:
 * Initializes the default clip table and optionally mirrors it into caller
 * storage while rebasing the global 0..255 lane pointer.
 */
extern "C" std::int32_t* mpvlib_InitClip(std::int32_t* clipTableStorage)
{
  std::int32_t* result = reinterpret_cast<std::int32_t*>(static_cast<std::intptr_t>(mpvlib_InitClip0255()));
  if (clipTableStorage != nullptr) {
    result = UTY_MemcpyDword(clipTableStorage, mpv_clip_0_255_tbl, kMpvClipTableDwordCount);
    mpv_clip_0_255_base = PointerToAddress(clipTableStorage + (kMpvClipTableBaseOffset / static_cast<int>(sizeof(std::int32_t))));
  }
  return result;
}

/**
 * Address: 0x00AE7AD0 (FUN_00AE7AD0, _mpvlib_InitClip0255)
 *
 * What it does:
 * Seeds clip table lanes as [0x180 bytes zero][0..255 ramp][0x180 bytes 0xFF]
 * and points global base to the ramp segment.
 */
extern "C" int mpvlib_InitClip0255()
{
  std::memset(mpv_clip_0_255_tbl, 0, kMpvClipTableBaseOffset);

  std::uint8_t* clipRamp = mpv_clip_0_255_tbl + kMpvClipTableBaseOffset;
  for (int i = 0; i < 0x100; ++i) {
    clipRamp[i] = static_cast<std::uint8_t>(i);
  }

  std::memset(clipRamp + 0x100, 0xFF, kMpvClipTableBaseOffset);
  mpv_clip_0_255_base = PointerToAddress(clipRamp);
  return -1;
}

/**
 * Address: 0x00AE7B10 (FUN_00AE7B10, _mpvlib_InitObjTbl)
 *
 * What it does:
 * Marks each allocated MPV object slot as active in the per-slot object table
 * lane.
 */
extern "C" void mpvlib_InitObjTbl()
{
  if (mpvlib_libwork.objectCount <= 0) {
    return;
  }

  auto* slot = reinterpret_cast<MPVObjectSlotView*>(AddressToMutablePointer(mpvlib_libwork.alignedWorkBaseAddress));
  for (int i = 0; i < mpvlib_libwork.objectCount; ++i) {
    slot->activeMarker = 1;
    slot = reinterpret_cast<MPVObjectSlotView*>(reinterpret_cast<std::uint8_t*>(slot) + kMpvObjectStrideBytes);
  }
}

/**
 * Address: 0x00AE7B40 (FUN_00AE7B40, _mpvlib_InitDct)
 *
 * What it does:
 * Initializes DCT runtime state and scale table lane rooted in the work
 * arena.
 */
extern "C" int mpvlib_InitDct(const int workAreaBaseAddress)
{
  DCT_FsriInit();
  return DCT_FsriInitScaleTbl(workAreaBaseAddress + kMpvDctScaleTableOffset);
}

/**
 * Address: 0x00AE7B60 (FUN_00AE7B60, _mpvlib_InitWork)
 *
 * What it does:
 * Aligns and clears MPV work memory, initializes conceal state, restores
 * default library condition lanes, and publishes key work pointers in global
 * runtime state.
 */
extern "C" std::int32_t* mpvlib_InitWork(const int objectCount, const int workMemoryBaseAddress)
{
  const int alignedWorkBaseAddress = (workMemoryBaseAddress + (kMpvWorkAlignBytes - 1)) & ~(kMpvWorkAlignBytes - 1);
  const unsigned int clearDwordCount = static_cast<unsigned int>((objectCount + 1) << 13) >> 2;
  UTY_MemsetDword(AddressToMutablePointer(alignedWorkBaseAddress), 0u, clearDwordCount);

  const int objectTableBaseAddress = alignedWorkBaseAddress + objectCount * kMpvObjectStrideBytes;
  const int concealStateBaseAddress = objectTableBaseAddress + kMpvConcealStateOffset;
  mpvlib_NoOpInitializeRange(AddressToMutablePointer(concealStateBaseAddress), kMpvConcealStateSizeBytes);

  std::int32_t* result = UTY_MemcpyDword(&mpvlib_libwork, mpvlib_cond_dfl, 16u);
  mpvlib_libwork.alignedWorkBaseAddress = alignedWorkBaseAddress;
  mpvlib_libwork.objectTableBaseAddress = objectTableBaseAddress;
  mpvlib_libwork.concealStateBaseAddress = concealStateBaseAddress;
  mpvlib_libwork.objectCount = objectCount;
  return result;
}

/**
 * Address: 0x00AE7BE0 (FUN_00AE7BE0, _MPV_Finish)
 *
 * What it does:
 * Finalizes MPV UMC and M2V lanes, then tears down conceal runtime state.
 */
extern "C" int MPV_Finish()
{
  MPVUMC_Finish();
  MPVM2V_Finish();
  return MPVCONCEAL_Finish(mpvlib_libwork.concealStateBaseAddress, kMpvConcealStateSizeBytes);
}

/**
 * Address: 0x00AE7C40 (FUN_00AE7C40, _mpvlib_SearchFreeHn)
 *
 * What it does:
 * Scans MPV handle slots and returns the first slot marked free.
 */
extern "C" int mpvlib_SearchFreeHn()
{
  const int objectCount = mpvlib_libwork.objectCount;
  int handleAddress = mpvlib_libwork.alignedWorkBaseAddress;
  for (int index = 0; index < objectCount; ++index) {
    if (AsHandleView(handleAddress)->objectSlotState == kMpvHandleSlotStateFree) {
      return handleAddress;
    }
    handleAddress += kMpvObjectStrideBytes;
  }
  return 0;
}

/**
 * Address: 0x00AE7E70 (FUN_00AE7E70, _mpvlib_InitPicAtr)
 *
 * What it does:
 * Writes default MPEG picture-attribute state for a freshly initialized
 * decoder handle.
 */
extern "C" int mpvlib_InitPicAtr(const int pictureAttributesAddress)
{
  auto* const attributes = reinterpret_cast<MPVPictureAttributes*>(AddressToMutablePointer(pictureAttributesAddress));

  std::fill_n(attributes->headerControlWords, 14, 0);
  attributes->pictureCodingType = 3;
  attributes->fullPelForwardVector = 1;
  attributes->fullPelBackwardVector = 1;
  attributes->concealMotionVectors = 1;
  attributes->reserved_48 = 0;
  attributes->reserved_4C = 0;

  attributes->forwardFCode = -1;
  attributes->backwardFCode = -1;
  attributes->intraDcPrecision = 0;
  attributes->pictureStructure = -1;
  attributes->topFieldFirst = -1;
  attributes->framePredFrameDct = -1;
  attributes->concealmentMotionVector = 0;
  attributes->qScaleType = 1;
  attributes->intraVlcFormat = 0;
  attributes->alternateScan = 0;
  attributes->repeatFirstField = 0;
  attributes->chroma420Type = -1;
  attributes->progressiveFrame = -1;
  attributes->compositeDisplayFlag = -1;
  attributes->vAxis = -1;
  attributes->fieldSequence = 0;
  attributes->subCarrier = -1;
  attributes->burstAmplitude = -1;
  attributes->subCarrierPhase = -1;
  attributes->extensionFlags = 0;
  return pictureAttributesAddress;
}

/**
 * Address: 0x00AE7D60 (FUN_00AE7D60, _mpvlib_InitObj)
 *
 * What it does:
 * Binds VLC tables, clip lanes, scratch addresses, and DCT callbacks into one
 * MPV handle object.
 */
extern "C" int mpvlib_InitObj(const int handleAddress)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  const int concealStateBaseAddress = mpvlib_libwork.concealStateBaseAddress;

  handle->runLevel8Address = PointerToAddress(mpvvlc_run_level_8);
  handle->runLevel4AddressMinus16 = PointerToAddress(mpvvlc_run_level_4) - 0x10;
  handle->runLevel2AddressMinus32 = PointerToAddress(mpvvlc_run_level_2) - 0x20;
  handle->runLevel1AddressMinus32 = PointerToAddress(mpvvlc_run_level_1) - 0x20;
  handle->runLevel0aAddress = PointerToAddress(mpvvlc_run_level_0a);
  handle->runLevel0bAddress = PointerToAddress(mpvvlc_run_level_0b);
  handle->runLevel0cAddress = PointerToAddress(mpvvlc_run_level_0c);

  handle->concealLaneAddress1120 = concealStateBaseAddress + 0x1120;
  handle->concealLaneAddress1100 = concealStateBaseAddress + 0x1100;
  handle->concealLaneAddress1160 = concealStateBaseAddress + 0x1160;
  handle->concealLaneAddress1260 = concealStateBaseAddress + 0x1260;
  handle->concealLaneAddress1280 = concealStateBaseAddress + 0x1280;

  handle->clipBaseAddress = mpv_clip_0_255_base;
  handle->clipBaseAddressMirror = mpv_clip_0_255_base;
  handle->scanLutBaseAddress = handleAddress + 0x3A0;
  handle->scanLutAddressD20 = handleAddress + 0xD20;
  handle->scanLutAddressEA0 = handleAddress + 0xEA0;

  handle->scanScratchAddress4A0 = handleAddress + 0x4A0;
  handle->scanScratchAddress520 = handleAddress + 0x520;
  handle->scanScratchAddress5A0 = handleAddress + 0x5A0;
  handle->scanScratchAddress620 = handleAddress + 0x620;
  handle->scanScratchAddress3A0 = handleAddress + 0x3A0;
  handle->scanScratchAddress420 = handleAddress + 0x420;

  handle->dctTransformSixBlocks = &DCT_FsriTrans6Blk;
  handle->dctTransformCbp = &DCT_FsriTransCbp;
  return handleAddress;
}

/**
 * Address: 0x00AE7C70 (FUN_00AE7C70, _mpvlib_InitHn)
 *
 * What it does:
 * Initializes one MPV handle lane after allocation, including callback
 * defaults, error state, picture attributes, and user stream hooks.
 */
extern "C" int mpvlib_InitHn(const int handleAddress)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);

  mpvlib_InitObj(handleAddress);
  handle->objectInitStatus = 0;
  UTY_MemcpyDword(handle->conditionCallbacks, &mpvlib_libwork, kMpvConditionCallbackDwordCount);
  MPVERR_InitErrInf(AddressToMutablePointer(handleAddress + 0x250));
  MPVCMC_InitObj(handle);
  mpvlib_InitDctPa(handleAddress);
  mpvlib_InitPicAtr(handleAddress + 0x1D0);

  handle->recoverNeededFlag = 0;
  handle->recoverState = 0;
  handle->decodeTablePrimary = mpvvlc_y_dcsiz;
  handle->decodeTableSecondary = mpvvlc_c_dcsiz;
  handle->pictureCodecClassification = 0;
  handle->sequenceStcCodePrimary = 0;
  handle->sequenceStcCodeSecondary = 0;
  handle->sequenceStcCodeTertiary = 0;
  handle->sequenceUserDataIdcPrecisionMode = 0;
  handle->decodeReadKernelIntra = &sub_AFAE50;
  handle->decodeReadKernelPredicted = &sub_AFD7C0;
  handle->serviceCountdown = handle->serviceReloadInterval;

  for (int streamIndex = 0; streamIndex < 4; ++streamIndex) {
    MPV_SetUsrSj(handleAddress, streamIndex, 0, 0, 0);
  }
  MPV_SetPicUsrBuf(handleAddress, 0, 0);

  handle->postCreateMarker = 0;
  handle->objectSlotState = kMpvHandleSlotStateAllocated;
  return handleAddress;
}

/**
 * Address: 0x00AE7C00 (FUN_00AE7C00, _MPV_Create)
 *
 * What it does:
 * Allocates a free MPV handle slot, initializes it, and attaches MPVM2V
 * runtime state.
 */
extern "C" int MPV_Create()
{
  const int freeHandleAddress = mpvlib_SearchFreeHn();
  if (freeHandleAddress == 0) {
    return 0;
  }

  mpvlib_NoOpInitializeRange(AddressToMutablePointer(freeHandleAddress), kMpvHandleSizeBytes);
  const int initializedHandleAddress = mpvlib_InitHn(freeHandleAddress);
  AsHandleView(initializedHandleAddress)->m2vDecoderHandle = MPVM2V_Create(initializedHandleAddress);
  return initializedHandleAddress;
}

/**
 * Address: 0x00AE7F10 (FUN_00AE7F10, _mpvlib_InitDctPa)
 *
 * What it does:
 * Initializes per-handle DCT plane state and binds per-handle DCT scratch
 * lanes used by decode kernels.
 */
extern "C" int mpvlib_InitDctPa(const int handleAddress)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  sub_AF7E40(&handle->dctPlaneState);
  handle->dctPlaneState.primaryScratchAddress = handleAddress + 0x6A0;
  handle->dctPlaneState.secondaryScratchAddress = handleAddress + 0x36C;
  handle->dctPlaneState.coefficientScratchAddress = handleAddress + 0xD20;
  return handle->dctPlaneState.coefficientScratchAddress;
}

/**
 * Address: 0x00AE7F40 (FUN_00AE7F40, _MPV_GetDctCnt)
 *
 * What it does:
 * Reads DCT primary/secondary decode counters from one MPV handle.
 */
extern "C" int MPV_GetDctCnt(const int handleAddress, int* const outPrimaryCount, int* const outSecondaryCount)
{
  MPVDctPlaneStateView* const dctPlaneState = &AsHandleView(handleAddress)->dctPlaneState;
  *outPrimaryCount = dctPlaneState->primaryDecodeCount;
  const int secondaryDecodeCount = dctPlaneState->secondaryDecodeCount;
  *outSecondaryCount = secondaryDecodeCount;
  return secondaryDecodeCount;
}

/**
 * Address: 0x00AE7F60 (FUN_00AE7F60, _MPV_Destroy)
 *
 * What it does:
 * Validates one MPV handle, tears down M2V/conceal lanes, and marks the
 * handle slot free again.
 */
extern "C" int MPV_Destroy(const int handleAddress)
{
  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidDestroyHandle);
  }

  MPVM2V_Destroy(handleAddress);
  MPVCONCEAL_Finish(handleAddress, kMpvHandleSizeBytes);
  AsHandleView(handleAddress)->objectSlotState = kMpvHandleSlotStateFree;
  return 0;
}

/**
 * Address: 0x00AE7FB0 (FUN_00AE7FB0, nullsub_48)
 *
 * What it does:
 * Preserved no-op initializer hook for per-range work-state lanes.
 */
extern "C" void mpvlib_NoOpInitializeRange(void* stateBaseAddress, const int stateSizeBytes)
{
  (void)stateBaseAddress;
  (void)stateSizeBytes;
}

/**
 * Address: 0x00AE7FC0 (FUN_00AE7FC0, _MPVCONCEAL_Finish)
 *
 * What it does:
 * Preserved no-op conceal teardown hook that forwards the first argument as
 * return value.
 */
extern "C" int MPVCONCEAL_Finish(const int concealStateBaseAddress, const int concealStateSizeBytes)
{
  (void)concealStateSizeBytes;
  return concealStateBaseAddress;
}

/**
 * Address: 0x00AE7FD0 (FUN_00AE7FD0, nullsub_26)
 *
 * What it does:
 * Default no-op callback used for condition slot 8 when no callback is
 * provided.
 */
extern "C" int mpvlib_DefaultConditionNoOp()
{
  return 0;
}

/**
 * Address: 0x00AE7FE0 (FUN_00AE7FE0, _MPV_SetCond)
 *
 * What it does:
 * Installs one condition callback globally or for a specific MPV handle, and
 * propagates the update into MPVM2V runtime state.
 */
extern "C" int MPV_SetCond(const int handleAddress, const int conditionIndex, int (*conditionCallback)())
{
  int (*resolvedCallback)() = conditionCallback;
  if (conditionIndex == kMpvConditionIndexConcealDefault && resolvedCallback == nullptr) {
    resolvedCallback = &mpvlib_DefaultConditionNoOp;
  }
  const int callbackAddress = static_cast<int>(reinterpret_cast<std::uintptr_t>(resolvedCallback));

  if (handleAddress == 0) {
    mpvlib_SetCondAll(conditionIndex, callbackAddress);
    mpvlib_libwork.conditionDefaults[conditionIndex] = static_cast<std::uint32_t>(callbackAddress);
    MPVM2V_SetCond(0, conditionIndex, callbackAddress);
    return 0;
  }

  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidSetCondHandle);
  }

  AsHandleView(handleAddress)->conditionCallbacks[conditionIndex] = callbackAddress;
  MPVM2V_SetCond(handleAddress, conditionIndex, callbackAddress);
  return 0;
}

/**
 * Address: 0x00AE8060 (FUN_00AE8060, _mpvlib_SetCondAll)
 *
 * What it does:
 * Broadcasts a condition callback to all currently allocated MPV handle slots.
 */
extern "C" int mpvlib_SetCondAll(const int conditionIndex, const int callbackAddress)
{
  int remainingObjectCount = mpvlib_libwork.objectCount;
  int handleAddress = mpvlib_libwork.alignedWorkBaseAddress;

  while (remainingObjectCount > 0) {
    MPVHandleInitView* const handle = AsHandleView(handleAddress);
    if (handle->objectSlotState == kMpvHandleSlotStateAllocated) {
      handle->conditionCallbacks[conditionIndex] = callbackAddress;
    }

    handleAddress += kMpvObjectStrideBytes;
    --remainingObjectCount;
  }
  return handleAddress;
}

/**
 * Address: 0x00AE80A0 (FUN_00AE80A0, _MPV_GetCond)
 *
 * What it does:
 * Reads one condition callback from global defaults or from a specific MPV
 * handle.
 */
extern "C" int MPV_GetCond(const int handleAddress, const int conditionIndex, int* const outCallbackAddress)
{
  if (handleAddress == 0) {
    *outCallbackAddress = static_cast<int>(mpvlib_libwork.conditionDefaults[conditionIndex]);
    return 0;
  }

  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidGetCondHandle);
  }

  *outCallbackAddress = AsHandleView(handleAddress)->conditionCallbacks[conditionIndex];
  return 0;
}

/**
 * Address: 0x00AE8100 (FUN_00AE8100, _MPVLIB_CheckHn)
 *
 * What it does:
 * Stores last checked handle for diagnostics and returns 0 for an allocated
 * MPV handle; otherwise returns -1.
 */
extern "C" int MPVLIB_CheckHn(const int handleAddress)
{
  mpvlib_deb_hn_last = handleAddress;
  if (handleAddress == 0) {
    return -1;
  }
  return AsHandleView(handleAddress)->objectSlotState == kMpvHandleSlotStateAllocated ? 0 : -1;
}

/**
 * Address: 0x00AE8120 (FUN_00AE8120, _MPVHDEC_Init)
 *
 * What it does:
 * Initializes MPV decode dispatch tables for normal and thumbnail decode lanes.
 */
extern "C" void MPVHDEC_Init()
{
  std::fill(std::begin(dec_mbs_func), std::end(dec_mbs_func), nullptr);
  std::fill(std::begin(skip_func), std::end(skip_func), nullptr);
  std::fill(std::begin(s_mc_intra_func), std::end(s_mc_intra_func), nullptr);
  std::fill(std::begin(s_mc_forward_func), std::end(s_mc_forward_func), nullptr);
  std::fill(std::begin(s_mc_backward_func), std::end(s_mc_backward_func), nullptr);
  std::fill(std::begin(s_mc_bidirect_func), std::end(s_mc_bidirect_func), nullptr);

  std::fill(std::begin(thumbnail_skip_func), std::end(thumbnail_skip_func), nullptr);
  std::fill(std::begin(thumbnail_mc_intra_func), std::end(thumbnail_mc_intra_func), nullptr);
  std::fill(std::begin(thumbnail_mc_forward_func), std::end(thumbnail_mc_forward_func), nullptr);
  std::fill(std::begin(thumbnail_mc_backward_func), std::end(thumbnail_mc_backward_func), nullptr);
  std::fill(std::begin(thumbnail_mc_bidirect_func), std::end(thumbnail_mc_bidirect_func), nullptr);

  dec_mbs_func[1] = &moho::movie::MPVDEC_DecIpicMb;
  dec_mbs_func[2] = &moho::movie::MPVDEC_DecPpicMb;
  dec_mbs_func[3] = &moho::movie::MPVDEC_DecBpicMb;

  skip_func[3] = &moho::movie::MPVUMC_BpicSkipped;
  skip_func[1] = &moho::movie::MPVUMC_PpicSkipped;
  skip_func[2] = &moho::movie::MPVUMC_PpicSkipped;
  s_mc_backward_func[3] = &moho::movie::MPVUMC_Backward;
  s_mc_intra_func[1] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[2] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[3] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[4] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[11] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[12] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[13] = &moho::movie::MPVUMC_Intra;
  s_mc_intra_func[14] = &moho::movie::MPVUMC_Intra;
  s_mc_bidirect_func[3] = &moho::movie::MPVUMC_BiDirect;
  s_mc_forward_func[2] = &moho::movie::MPVUMC_Forward;
  s_mc_forward_func[3] = &moho::movie::MPVUMC_Forward;

  thumbnail_skip_func[3] = &MPVUMCT_BpicSkipped;
  thumbnail_skip_func[1] = &MPVUMCT_PpicSkipped;
  thumbnail_skip_func[2] = &MPVUMCT_PpicSkipped;
  thumbnail_mc_backward_func[3] = &MPVUMCT_Backward;
  thumbnail_mc_intra_func[1] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[2] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[3] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[4] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[11] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[12] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[13] = &MPVUMCT_Intra;
  thumbnail_mc_intra_func[14] = &MPVUMCT_Intra;
  thumbnail_mc_bidirect_func[3] = &MPVUMCT_BiDirect;
  thumbnail_mc_forward_func[2] = &MPVUMCT_Forward;
  thumbnail_mc_forward_func[3] = &MPVUMCT_Forward;
}

/**
 * Address: 0x00AE8270 (FUN_00AE8270, _MPV_SetUsrSj)
 *
 * What it does:
 * Stores one user stream object/callback/context triple in the handle stream
 * lane table.
 */
extern "C" std::int32_t* MPV_SetUsrSj(
  const int handleAddress, const int streamIndex, const int streamObjectAddress, const int streamCallbackAddress,
  const int streamContextAddress
)
{
  MPVUserSjLane* const lane = &AsHandleView(handleAddress)->userSjLanes[streamIndex];
  lane->streamObjectAddress = streamObjectAddress;
  lane->streamCallbackAddress = streamCallbackAddress;
  lane->streamContextAddress = streamContextAddress;
  return reinterpret_cast<std::int32_t*>(lane);
}

/**
 * Address: 0x00AE82A0 (FUN_00AE82A0, _MPV_SetPicUsrBuf)
 *
 * What it does:
 * Sets picture-user buffer/context fields and clears per-picture decode-state
 * latch.
 */
extern "C" std::int32_t* MPV_SetPicUsrBuf(const int handleAddress, const int userBufferAddress, const int userContextAddress)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  handle->pictureUserBufferAddress = userBufferAddress;
  handle->pictureUserContextAddress = userContextAddress;
  handle->pictureUserDecodeState = 0;
  return reinterpret_cast<std::int32_t*>(handle);
}

/**
 * Address: 0x00AE82D0 (FUN_00AE82D0, _MPV_GetPicUsr)
 *
 * What it does:
 * Reads picture-user buffer and decode-state fields from one handle into
 * optional outputs.
 */
extern "C" int* MPV_GetPicUsr(const int handleAddress, int* const outUserBufferAddress, int* const outDecodeState)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  if (outUserBufferAddress != nullptr) {
    *outUserBufferAddress = handle->pictureUserBufferAddress;
  }
  if (outDecodeState != nullptr) {
    *outDecodeState = handle->pictureUserDecodeState;
  }
  return outDecodeState;
}

/**
 * Address: 0x00AE8300 (FUN_00AE8300, _MPV_DecodePicAtrSj)
 *
 * What it does:
 * Decodes picture attributes from SJ stream lanes, including delimiter-walk
 * recovery loop and M2V codec fast path.
 */
extern "C" int MPV_DecodePicAtrSj(const int handleAddress, MPVSjStream* const stream)
{
  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidDecodePicAtrHandle);
  }

  AsHandleView(handleAddress)->pictureUserDecodeState = 0;

  MPVSjChunk streamChunk{};
  SjRequestChunk(stream, streamChunk);
  SjSubmitTailChunk(stream, streamChunk);

  MPVSjChunk codecProbeChunk = streamChunk;
  if (mpvhdec_GetCodec(handleAddress, &codecProbeChunk) == 2) {
    return MPVM2V_DecodePicAtr(handleAddress, stream);
  }

  int recoverStatus = MPVHDEC_RecoverSj(handleAddress, -1, stream);
  if (recoverStatus != 0) {
    return MPVERR_SetCode(handleAddress, recoverStatus);
  }

  while (true) {
    const int delimiter = mpvhdec_GetCurDelim(stream);
    if (delimiter == 0 || (delimiter & 3) != 0) {
      return recoverStatus;
    }
    if ((delimiter & 0x80) != 0) {
      return -2;
    }

    switch (delimiter) {
      case 4:
        mpvhdec_DecPscSj(handleAddress, stream);
        break;
      case 8:
        mpvhdec_DecGscSj(handleAddress, stream);
        break;
      case 16:
        mpvhdec_DecEscSj(handleAddress, stream);
        break;
      case 32:
        mpvhdec_DecUdscSj(handleAddress, stream);
        break;
      case 64:
        mpvhdec_DecShcSj(handleAddress, stream);
        break;
      default:
        break;
    }

    recoverStatus = MPVHDEC_RecoverSj(handleAddress, -1, stream);
    if (recoverStatus != 0) {
      return MPVERR_SetCode(handleAddress, recoverStatus);
    }
  }
}

/**
 * Address: 0x00AE84C0 (FUN_00AE84C0, _mpvhdec_GetCurDelim)
 *
 * What it does:
 * Probes the current SJ stream chunk and returns delimiter type when at least
 * four bytes are available, otherwise returns zero.
 */
extern "C" int mpvhdec_GetCurDelim(MPVSjStream* const stream)
{
  MPVSjChunk chunk{};
  SjRequestChunk(stream, chunk);
  SjSubmitTailChunk(stream, chunk);
  if (chunk.size >= 4) {
    return MPV_CheckDelim(chunk.data);
  }
  return 0;
}

/**
 * Address: 0x00AE8510 (FUN_00AE8510, _MPV_DecodePicAtr)
 *
 * What it does:
 * Wraps picture-attribute decode over an SJ memory stream and reports consumed
 * bytes.
 */
extern "C" int MPV_DecodePicAtr(const int handleAddress, const int* const pictureDataRange, int* const outConsumedBytes)
{
  const auto* const bufferRange = reinterpret_cast<const MPVPictureDataRange*>(pictureDataRange);
  moho::SofdecSjMemoryHandle* const sjMemoryHandle = SJMEM_Create(bufferRange->bufferAddress, bufferRange->bufferSize);
  if (sjMemoryHandle == nullptr) {
    return -1;
  }

  const int decodeResult = MPV_DecodePicAtrSj(handleAddress, reinterpret_cast<MPVSjStream*>(sjMemoryHandle));
  *outConsumedBytes = bufferRange->bufferSize - SJMEM_GetNumData(sjMemoryHandle, 1);
  SJMEM_Destroy(sjMemoryHandle);
  return decodeResult;
}

/**
 * Address: 0x00AE8570 (FUN_00AE8570, _mpvhdec_GetCodec)
 *
 * What it does:
 * Classifies stream codec state for one handle by scanning delim markers in
 * current chunk and caching result in handle state.
 */
extern "C" int mpvhdec_GetCodec(const int handleAddress, MPVSjChunk* const chunk)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  if (handle->pictureCodecClassification != 0) {
    return handle->pictureCodecClassification;
  }

  const std::uint8_t* const sequenceHeader = MPV_SearchDelim(reinterpret_cast<const std::uint8_t*>(chunk->data), chunk->size, 64);
  if (sequenceHeader != nullptr) {
    const std::uint8_t* const probeStart = sequenceHeader + 4;
    const int remainingBytes = chunk->size - static_cast<int>(probeStart - reinterpret_cast<const std::uint8_t*>(chunk->data));
    const std::uint8_t* const nextDelimiter = MPV_SearchDelim(probeStart, remainingBytes, -1);
    if (nextDelimiter != nullptr) {
      const int delimiterType = MPV_CheckDelim(nextDelimiter);
      if ((delimiterType & 0x10) != 0) {
        handle->pictureCodecClassification = 2;
        return handle->pictureCodecClassification;
      }
      if (delimiterType != 0) {
        handle->pictureCodecClassification = 1;
      }
    }
  }

  return handle->pictureCodecClassification;
}

/**
 * Address: 0x00AE8BD0 (FUN_00AE8BD0, _mpvhdec_InitIqm)
 *
 * What it does:
 * Restores the default intra quantization matrix into the active decode
 * scratch lane.
 */
extern "C" std::int32_t* mpvhdec_InitIqm(const int handleAddress)
{
  auto* const decodeContext = reinterpret_cast<MPVDecoderScanContext*>(AsHandleView(handleAddress));
  return UTY_MemcpyDword(decodeContext->decodeWorkScratchIntra, mpvbdec_dfl_iqm, 16u);
}

/**
 * Address: 0x00AE8BF0 (FUN_00AE8BF0, _mpvhdec_InitNqm)
 *
 * What it does:
 * Fills the non-intra quantization matrix lane with the canonical `0x10`
 * coefficients.
 */
extern "C" std::int32_t* mpvhdec_InitNqm(const int handleAddress)
{
  auto* const decodeContext = reinterpret_cast<MPVDecoderScanContext*>(AsHandleView(handleAddress));
  UTY_MemsetDword(decodeContext->decodeWorkScratchPredicted, 0x10101010u, 16u);
  return reinterpret_cast<std::int32_t*>(decodeContext->decodeWorkScratchPredicted);
}

/**
 * Address: 0x00AE85F0 (FUN_00AE85F0, _mpvhdec_DecShcSj)
 *
 * What it does:
 * Decodes one sequence header start-code payload from SJ stream state,
 * including optional quantization matrix loads and derived macroblock geometry.
 */
extern "C" int mpvhdec_DecShcSj(const int handleAddress, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  auto* const decodeContext = reinterpret_cast<MPVDecoderScanContext*>(handle);

  int& sequenceHorizontalSize = handle->pictureAttributes.headerControlWords[0];
  int& sequenceVerticalSize = handle->pictureAttributes.headerControlWords[1];
  int& sequenceFrameRateCode = handle->pictureAttributes.headerControlWords[4];
  int& sequenceHeaderCount = handle->pictureAttributes.headerControlWords[13];

  handle->currentHeaderContext = 1;
  ++sequenceHeaderCount;
  handle->headerProgressPrimary = 0;
  handle->headerProgressSecondary = 0;
  handle->pictureAttributes.extensionFlags = 0;

  MPVBitstreamState bitstreamState{};
  LoadHeaderChunkBitstream(handle, stream, bitstreamState);

  sequenceHorizontalSize = static_cast<int>(ConsumeHeaderBits(bitstreamState, 12));
  sequenceVerticalSize = static_cast<int>(ConsumeHeaderBits(bitstreamState, 12));
  handle->sequenceAspectRatioCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 4));
  sequenceFrameRateCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 4));
  handle->sequenceBitRateCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 18));
  (void)ConsumeHeaderFlag(bitstreamState); // marker bit
  handle->sequenceVbvBufferCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 10));
  handle->constrainedParametersFlag = static_cast<int>(ConsumeHeaderFlag(bitstreamState));

  if (ConsumeHeaderFlag(bitstreamState)) {
    LoadQuantizationMatrix(bitstreamState, decodeContext->decodeWorkScratchIntra);
  } else {
    mpvhdec_InitIqm(handleAddress);
  }

  if (ConsumeHeaderFlag(bitstreamState)) {
    LoadQuantizationMatrix(bitstreamState, decodeContext->decodeWorkScratchPredicted);
  } else {
    mpvhdec_InitNqm(handleAddress);
  }

  decodeContext->macroblocksPerRow = (sequenceHorizontalSize + 15) >> 4;
  decodeContext->macroblockRowsCount = (sequenceVerticalSize + 15) >> 4;
  decodeContext->macroblockLinearLimit = decodeContext->macroblocksPerRow * decodeContext->macroblockRowsCount - 1;

  handle->pictureAttributes.reserved_48 = handle->sequenceBitRateCode;
  handle->pictureAttributes.reserved_4C = handle->sequenceVbvBufferCode;
  handle->pictureAttributes.qScaleType = static_cast<std::int8_t>(handle->sequenceAspectRatioCode);
  handle->pictureAttributes.intraVlcFormat = static_cast<std::int8_t>(handle->constrainedParametersFlag);

  CommitHeaderChunkSplit(handle, stream, ComputeHeaderChunkSplitOffset(handle, bitstreamState));
  return 0;
}

/**
 * Address: 0x00AE8C10 (FUN_00AE8C10, _mpvhdec_DecGscSj)
 *
 * What it does:
 * Decodes one group-of-pictures header from SJ stream state and stores GOP
 * time-code/flag fields in the active handle state.
 */
extern "C" int mpvhdec_DecGscSj(const int handleAddress, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  int& groupHeaderCount = handle->pictureAttributes.headerControlWords[12];
  int& gopTimeCodePacked = handle->pictureAttributes.headerControlWords[7];
  int& gopHours = handle->pictureAttributes.headerControlWords[8];
  int& gopMinutes = handle->pictureAttributes.headerControlWords[9];
  int& gopSeconds = handle->pictureAttributes.headerControlWords[10];
  int& gopPictures = handle->pictureAttributes.headerControlWords[11];

  handle->currentHeaderContext = 2;
  ++groupHeaderCount;
  handle->headerProgressPrimary = 0;
  handle->headerProgressSecondary = 0;
  handle->pictureAttributes.extensionFlags = 0;

  MPVBitstreamState bitstreamState{};
  LoadHeaderChunkBitstream(handle, stream, bitstreamState);

  const int gopTimeCodeBits = static_cast<int>(ConsumeHeaderBits(bitstreamState, 25));
  gopPictures = gopTimeCodeBits & 0x3F;
  gopSeconds = (gopTimeCodeBits >> 6) & 0x3F;
  gopMinutes = (gopTimeCodeBits >> 13) & 0x3F;
  gopTimeCodePacked = (gopTimeCodeBits >> 16) & 0xFF;
  gopHours = (gopTimeCodeBits >> 19) & 0x1F;

  handle->gopClosedFlag = static_cast<int>(ConsumeHeaderFlag(bitstreamState));
  handle->gopBrokenLinkFlag = static_cast<int>(ConsumeHeaderFlag(bitstreamState));

  CommitHeaderChunkSplit(handle, stream, ComputeHeaderChunkSplitOffset(handle, bitstreamState));
  return 0;
}

/**
 * Address: 0x00AE8DF0 (FUN_00AE8DF0, _mpvhdec_DecPscSj)
 *
 * What it does:
 * Decodes picture-header fields from SJ stream state and refreshes macroblock
 * dispatch function lanes for the active picture coding type.
 */
extern "C" int mpvhdec_DecPscSj(const int handleAddress, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  int& pictureTemporalReference = handle->pictureAttributes.headerControlWords[5];
  int& pictureCodingType = handle->pictureAttributes.headerControlWords[6];

  handle->currentHeaderContext = 3;

  MPVBitstreamState bitstreamState{};
  LoadHeaderChunkBitstream(handle, stream, bitstreamState);

  pictureTemporalReference = static_cast<int>(ConsumeHeaderBits(bitstreamState, 10));
  pictureCodingType = static_cast<int>(ConsumeHeaderBits(bitstreamState, 3));
  handle->pictureVbvDelay = static_cast<int>(ConsumeHeaderBits(bitstreamState, 16));

  if (pictureCodingType == 1 || pictureCodingType == 2) {
    handle->headerProgressSecondary = 0;
    ++handle->headerProgressPrimary;
    handle->pictureAttributes.extensionFlags = handle->headerProgressPrimary << 16;
  } else {
    ++handle->headerProgressSecondary;
    handle->pictureAttributes.extensionFlags = ((handle->headerProgressPrimary << 16) - 0x10000) | handle->headerProgressSecondary;
  }

  if (pictureCodingType == 2 || pictureCodingType == 3) {
    handle->fullPelForwardVector = static_cast<int>(ConsumeHeaderFlag(bitstreamState));

    const int forwardFCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 3));
    handle->forwardFCodeMinus1 = forwardFCode - 1;
    handle->forwardFCodeWrapShift = 27 - handle->forwardFCodeMinus1;
    handle->forwardFCodeScale = 1 << handle->forwardFCodeMinus1;

    if (pictureCodingType == 3) {
      handle->fullPelBackwardVector = static_cast<int>(ConsumeHeaderFlag(bitstreamState));

      const int backwardFCode = static_cast<int>(ConsumeHeaderBits(bitstreamState, 3));
      handle->backwardFCodeMinus1 = backwardFCode - 1;
      handle->backwardFCodeWrapShift = 27 - handle->backwardFCodeMinus1;
      handle->backwardFCodeScale = 1 << handle->backwardFCodeMinus1;
    }
  }

  const bool frameModeProfile = (handle->conditionCallbacks[6] == 3);
  const int profileBias = frameModeProfile ? 0 : 1;
  const int dispatchIndex = pictureCodingType + profileBias * 5;
  const int intraDispatchIndex = 10 * handle->conditionCallbacks[4] + pictureCodingType + profileBias * 5;

  handle->decodeReadKernelPrimary = reinterpret_cast<MPVMacroblockDecodeFn>(&sub_C0E1B0);
  handle->decodeReadKernelSecondary = reinterpret_cast<MPVMacroblockDecodeFn>(&sub_C0E2E0);
  handle->decodeMacroblockByType = dec_mbs_func[pictureCodingType];

  if (handle->conditionCallbacks[10] != 0) {
    handle->decodeSkipRunByType = thumbnail_skip_func[dispatchIndex];
    handle->decodeIntraMacroblockByType = thumbnail_mc_intra_func[intraDispatchIndex];
    handle->decodePredictedMode1 = thumbnail_mc_backward_func[dispatchIndex];
    handle->decodePredictedMode2 = thumbnail_mc_forward_func[dispatchIndex];
    handle->decodePredictedMode3 = thumbnail_mc_bidirect_func[dispatchIndex];
  } else {
    handle->decodeSkipRunByType = skip_func[dispatchIndex];
    handle->decodeIntraMacroblockByType = s_mc_intra_func[intraDispatchIndex];
    handle->decodePredictedMode1 = s_mc_backward_func[dispatchIndex];
    handle->decodePredictedMode2 = s_mc_forward_func[dispatchIndex];
    handle->decodePredictedMode3 = s_mc_bidirect_func[dispatchIndex];
  }
  handle->decodePredictedMode0 = handle->decodePredictedMode2;

  while (ConsumeHeaderFlag(bitstreamState)) {
    (void)ConsumeHeaderBits(bitstreamState, 8);
    if (ComputeHeaderChunkSplitOffset(handle, bitstreamState) >= handle->activeHeaderChunk.size) {
      return -3;
    }
  }

  CommitHeaderChunkSplit(handle, stream, ComputeHeaderChunkSplitOffset(handle, bitstreamState));
  return 0;
}

/**
 * Address: 0x00AE93A0 (FUN_00AE93A0, _mpvhdec_DecEscSj)
 *
 * What it does:
 * Consumes one extension start-code delimiter payload lane from SJ stream state
 * and advances to the next delimiter.
 */
extern "C" int mpvhdec_DecEscSj(const int handleAddress, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  SjRequestChunk(stream, handle->activeHeaderChunk);
  CommitHeaderChunkSplit(handle, stream, kMpvStartCodeByteCount);
  MPV_GoNextDelimSj(stream);
  return 0;
}

/**
 * Address: 0x00AE9420 (FUN_00AE9420, _mpvhdec_DecUdscSj)
 *
 * What it does:
 * Parses user-data start-code payload through the user-data analyzer, commits
 * consumed bytes, and advances to the next delimiter.
 */
extern "C" int mpvhdec_DecUdscSj(const int handleAddress, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  SjRequestChunk(stream, handle->activeHeaderChunk);

  const int analyzeResult = mpvhdec_AnalyUd(
    reinterpret_cast<std::int32_t*>(handle),
    handle->activeHeaderChunk.data,
    handle->activeHeaderChunk.size
  );

  CommitHeaderChunkSplit(handle, stream, kMpvStartCodeByteCount);
  MPV_GoNextDelimSj(stream);
  return analyzeResult;
}

/**
 * Address: 0x00AE9650 (FUN_00AE9650, _mpvhdec_DecSeqUdsc)
 *
 * What it does:
 * Parses sequence user-data directives (`IDCPREC`, `STCCODE`) and updates
 * decode kernel/table lanes for subsequent slice parsing.
 */
extern "C" int mpvhdec_DecSeqUdsc(std::int32_t* const handleWords, const std::uint8_t* const userDataStart, const int consumedByteCount)
{
  auto* const handle = reinterpret_cast<MPVHandleInitView*>(handleWords);
  const std::uint8_t* const payloadStart = userDataStart + 4;
  const int payloadBytes = consumedByteCount - 4;

  for (int offset = 0; offset < payloadBytes; ++offset) {
    const char* const cursor = reinterpret_cast<const char*>(payloadStart + offset);
    if (std::strncmp(cursor, "IDCPREC", 7) == 0) {
      handle->sequenceUserDataIdcPrecisionMode = (std::atoi(cursor + 16) != 0) ? 3 : 0;
    }
    if (std::strncmp(cursor, "STCCODE", 7) == 0) {
      handle->sequenceStcCodePrimary = std::atoi(cursor + 16);
      handle->sequenceStcCodeSecondary = std::atoi(cursor + 24);
      handle->sequenceStcCodeTertiary = std::atoi(cursor + 32);
    }
    if (MPV_CheckDelim(payloadStart + offset) != 0) {
      break;
    }
  }

  const bool useIdcPrecisionKernel = (handle->sequenceUserDataIdcPrecisionMode != 0);
  handle->decodeReadKernelIntra = useIdcPrecisionKernel ? &mpvhdec_ReadKernelIntraIdcPrec3 : &sub_AFAE50;
  handle->decodeTablePrimary = useIdcPrecisionKernel ? mpvvlc2_y_dcsiz : mpvvlc_y_dcsiz;
  handle->decodeTableSecondary = useIdcPrecisionKernel ? mpvvlc2_c_dcsiz : mpvvlc_c_dcsiz;

  if (handle->sequenceStcCodePrimary == 8) {
    return -1;
  }

  handle->decodeReadKernelPredicted = &sub_AFD7C0;
  return 0;
}

/**
 * Address: 0x00AE94C0 (FUN_00AE94C0, _mpvhdec_AnalyUd)
 *
 * What it does:
 * Scans user-data payload up to the next delimiter, forwards bytes into the
 * configured user stream sink/callback lane, and applies sequence user-data
 * directives when running in sequence context.
 */
extern "C" int mpvhdec_AnalyUd(std::int32_t* const handleWords, std::uint8_t* const userDataStart, const int chunkSize)
{
  auto* const handle = reinterpret_cast<MPVHandleInitView*>(handleWords);
  int userDataStatus = 0;
  int fallbackStatus = 0;

  const int currentHeaderContext = handle->currentHeaderContext;
  const int scanStop = chunkSize - 3;
  int consumedBytes = 4;
  for (; consumedBytes < scanStop; ++consumedBytes) {
    if (MPV_CheckDelim(userDataStart + consumedBytes) != 0) {
      break;
    }
  }
  if (consumedBytes == scanStop) {
    fallbackStatus = -1;
  }

  if (currentHeaderContext == 1) {
    userDataStatus = mpvhdec_DecSeqUdsc(handleWords, userDataStart, consumedBytes);
  }

  if (currentHeaderContext >= 0 && currentHeaderContext < 4) {
    MPVUserSjLane& userLane = handle->userSjLanes[currentHeaderContext];
    if (userLane.streamObjectAddress != 0) {
      MPVSjChunk sinkChunk{};
      UserDataSinkRequestChunk(userLane.streamObjectAddress, consumedBytes, sinkChunk);

      const int firstCopyBytes = std::min(sinkChunk.size, consumedBytes);
      std::memcpy(sinkChunk.data, userDataStart, static_cast<std::size_t>(firstCopyBytes));
      sinkChunk.size = firstCopyBytes;
      UserDataSinkSubmitChunk(userLane.streamObjectAddress, sinkChunk);

      if (firstCopyBytes < consumedBytes) {
        MPVSjChunk tailSinkChunk{};
        const int remainingBytes = consumedBytes - firstCopyBytes;
        UserDataSinkRequestChunk(userLane.streamObjectAddress, remainingBytes, tailSinkChunk);
        const int tailCopyBytes = std::min(tailSinkChunk.size, remainingBytes);
        std::memcpy(tailSinkChunk.data, userDataStart + firstCopyBytes, static_cast<std::size_t>(tailCopyBytes));
        tailSinkChunk.size = tailCopyBytes;
        UserDataSinkSubmitChunk(userLane.streamObjectAddress, tailSinkChunk);
      }

      if (userLane.streamCallbackAddress != 0) {
        auto* const callback = reinterpret_cast<void(__cdecl*)(int, int)>(static_cast<std::uintptr_t>(userLane.streamCallbackAddress));
        callback(userLane.streamContextAddress, currentHeaderContext);
      }
    }
  }

  if (currentHeaderContext == 3 && handle->pictureUserBufferAddress != 0) {
    const int userCopyBytes = std::max(0, std::min(consumedBytes, handle->pictureUserContextAddress));
    std::memcpy(AddressToMutablePointer(handle->pictureUserBufferAddress), userDataStart, static_cast<std::size_t>(userCopyBytes));
    handle->pictureUserDecodeState = userCopyBytes;
  }

  return (userDataStatus != 0) ? userDataStatus : fallbackStatus;
}

/**
 * Address: 0x00AE9F10 (FUN_00AE9F10, _MPV_CheckDelim)
 *
 * What it does:
 * Classifies one MPEG start-code word into decoder delimiter categories used by
 * MPV stream scanning paths.
 */
extern "C" int MPV_CheckDelim(const std::uint8_t* const bitstreamCursor)
{
  const std::uint32_t startCodeWord = ReadBigEndianWord(bitstreamCursor);
  if (startCodeWord == 0x00000100u) {
    return 4;
  }
  if (startCodeWord == 0x00000101u) {
    return 3;
  }
  if (startCodeWord > 0x00000101u && startCodeWord <= 0x000001AFu) {
    return 1;
  }

  switch (startCodeWord) {
    case 0x000001B2u:
      return 32;
    case 0x000001B3u:
      return 64;
    case 0x000001B5u:
      return 16;
    case 0x000001B7u:
      return 128;
    case 0x000001B8u:
      return 8;
    default:
      return 0;
  }
}

/**
 * Address: 0x00AE9FB0 (FUN_00AE9FB0, _MPV_BsearchDelim)
 *
 * What it does:
 * Scans backward from one-past-end cursor for MPEG start-code delimiters and
 * returns the first delimiter that matches the caller mask.
 */
extern "C" std::uint8_t* MPV_BsearchDelim(std::uint8_t* const bitstreamCursor, const unsigned int scanLengthBytes, const int delimiterMask)
{
  std::uintptr_t cursorAddress = reinterpret_cast<std::uintptr_t>(bitstreamCursor);
  const std::uintptr_t scanBeginAddress = cursorAddress - static_cast<std::uintptr_t>(scanLengthBytes);
  int state = 0;

  if (scanBeginAddress >= cursorAddress) {
    return nullptr;
  }

  while (true) {
    --cursorAddress;
    auto* const cursor = reinterpret_cast<std::uint8_t*>(cursorAddress);
    const std::uint8_t currentByte = *cursor;

    switch (state) {
      case 0:
        state = 1;
        break;
      case 1:
        if (currentByte == 1) {
          state = 2;
        }
        break;
      case 2:
        if (currentByte == 0) {
          state = 3;
        } else if (currentByte != 1) {
          state = 1;
        }
        break;
      case 3:
        if (currentByte == 0) {
          if ((MPV_CheckDelim(cursor) & delimiterMask) != 0) {
            return cursor;
          }
          state = 0;
        } else {
          state = (currentByte == 1) ? 2 : 1;
        }
        break;
      default:
        break;
    }

    if (scanBeginAddress >= cursorAddress) {
      return nullptr;
    }
  }
}

/**
 * Address: 0x00AEA040 (FUN_00AEA040, _MPV_SearchDelim)
 *
 * What it does:
 * Scans forward across a byte range and returns the first MPEG start-code
 * delimiter that matches the caller mask.
 */
extern "C" std::uint8_t* MPV_SearchDelim(const std::uint8_t* const bitstreamCursor, const int scanLengthBytes, const int delimiterMask)
{
  std::uintptr_t cursorAddress = reinterpret_cast<std::uintptr_t>(bitstreamCursor);
  const std::uintptr_t scanEndAddress = cursorAddress + static_cast<std::uintptr_t>(scanLengthBytes);
  int state = 0;

  if (cursorAddress >= scanEndAddress) {
    return nullptr;
  }

  while (true) {
    const auto* const cursor = reinterpret_cast<const std::uint8_t*>(cursorAddress);
    const std::uint8_t currentByte = *cursor;
    ++cursorAddress;

    switch (state) {
      case 0:
        if (currentByte == 0) {
          state = 1;
        }
        break;
      case 1:
        state = (currentByte == 0) ? 2 : 0;
        break;
      case 2:
        if (currentByte == 1) {
          state = 3;
        } else if (currentByte != 0) {
          state = 0;
        }
        break;
      case 3:
        if ((MPV_CheckDelim(reinterpret_cast<const std::uint8_t*>(cursorAddress - 4u)) & delimiterMask) != 0) {
          return reinterpret_cast<std::uint8_t*>(cursorAddress - 4u);
        }
        state = 0;
        break;
      default:
        break;
    }

    if (cursorAddress >= scanEndAddress) {
      return nullptr;
    }
  }
}

/**
 * Address: 0x00AE9A10 (FUN_00AE9A10, _MPVHDEC_RecoverSj)
 *
 * What it does:
 * Recovers SJ stream position to required delimiter mask and updates per-handle
 * recovery counters/flags.
 */
extern "C" int MPVHDEC_RecoverSj(const int handleAddress, const int expectedDelimiterMask, MPVSjStream* const stream)
{
  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  const int conditionLaneValue = handle->conditionCallbacks[1];

  if (handle->recoverNeededFlag != 0) {
    ++handle->recoverState;
    handle->recoverNeededFlag = 0;
    ++handle->recoverEventCounter;
    if (conditionLaneValue == 0) {
      return -2;
    }
    ++handle->recoverConditionCounter;
  }

  const int fallbackStatus = (conditionLaneValue != 0) ? -3 : -2;
  int delimiter = MPV_GoNextDelimSj(stream);
  if (delimiter == 0) {
    return fallbackStatus;
  }

  while ((delimiter & expectedDelimiterMask) == 0) {
    if (MPV_MoveChunk(stream, 1, 4) != 4) {
      return fallbackStatus;
    }
    delimiter = MPV_GoNextDelimSj(stream);
    if (delimiter == 0) {
      return fallbackStatus;
    }
  }
  return 0;
}

/**
 * Address: 0x00AE9AB0 (FUN_00AE9AB0, _MPV_MoveChunk)
 *
 * What it does:
 * Requests a chunk slice from one lane, ungets it to the opposite lane policy,
 * and returns moved byte count.
 */
extern "C" int MPV_MoveChunk(MPVSjStream* const stream, const int lane, const int byteCount)
{
  MPVSjChunk chunk{};
  AsSjStreamView(stream)->vtable->requestChunk(stream, lane, byteCount, &chunk);
  AsSjStreamView(stream)->vtable->releaseChunk(stream, lane == 0 ? 1 : 0, &chunk);
  return chunk.size;
}

/**
 * Address: 0x00AEAB20 (FUN_00AEAB20, _MPV_DecodeFrmSj)
 *
 * What it does:
 * Decodes one frame from SJ stream lanes, exports the handle picture-attribute
 * block, and returns recovery-counter deltas through the decode session.
 */
extern "C" int MPV_DecodeFrmSj(const int handleAddress, MPVSjStream* const stream, MPVFrameDecodeSession* const frameSession)
{
  if (MPVLIB_CheckHn(handleAddress) != 0) {
    return MPVERR_SetCode(0, kMpvErrInvalidDecodeFrameHandle);
  }

  MPVHandleInitView* const handle = AsHandleView(handleAddress);
  if (handle->pictureCodecClassification == 2) {
    return MPVM2V_DecodeFrm(handleAddress, stream, frameSession);
  }

  const int recoverEventCounterBefore = handle->recoverEventCounter;
  const int recoverConditionCounterBefore = handle->recoverConditionCounter;

  std::memcpy(handle->reserved_264, frameSession, sizeof(*frameSession));
  MPVUMC_InitOutRfb(handleAddress);
  MPVCMC_InitMcOiRt(handleAddress);
  MPVCMC_SetCcnt(handleAddress);
  MPVBDEC_StartFrame(handleAddress);

  const int decodeResult = MPVSL_DecPicture(handleAddress, stream);
  MPVUMC_EndOfFrame(handleAddress);

  auto* const outPictureAttributes = reinterpret_cast<MPVPictureAttributeExportBlock*>(
    AddressToMutablePointer(frameSession->pictureAttributesAddress)
  );
  const auto* const handlePictureAttributes =
    reinterpret_cast<const MPVPictureAttributeExportBlock*>(&handle->pictureAttributes);
  std::memcpy(outPictureAttributes, handlePictureAttributes, sizeof(*handlePictureAttributes));

  if (handle->conditionCallbacks[10] != 0) {
    outPictureAttributes->pictureAttributes.headerControlWords[0] =
      SignedRoundUpShift(outPictureAttributes->pictureAttributes.headerControlWords[0], 3);
    outPictureAttributes->pictureAttributes.headerControlWords[1] =
      SignedRoundUpShift(outPictureAttributes->pictureAttributes.headerControlWords[1], 3);
    outPictureAttributes->pictureAttributes.headerControlWords[2] =
      SignedRoundUpShift(outPictureAttributes->pictureAttributes.headerControlWords[0], 4);
    outPictureAttributes->pictureAttributes.headerControlWords[3] =
      SignedRoundUpShift(outPictureAttributes->pictureAttributes.headerControlWords[1], 4);
  }

  frameSession->recoverEventDelta = handle->recoverEventCounter - recoverEventCounterBefore;
  frameSession->recoverConditionDelta = handle->recoverConditionCounter - recoverConditionCounterBefore;
  return decodeResult;
}

/**
 * Address: 0x00AF63A0 (FUN_00AF63A0, _MPVVLC_Init)
 *
 * What it does:
 * Initializes all static MPV VLC seed tables and, when a runtime setup
 * context is provided, builds runtime VLC lanes into that context.
 */
extern "C" int MPVVLC_Init(const int vlcContextBase)
{
  mpvvlc_InitMbai();
  mpvvlc_InitMbType();
  mpvvlc_InitMotion();
  mpvvlc_InitCbp();
  mpvvlc_InitDcSiz();
  mpvvlc_InitRunLevel();
  mpvvlc_SetDflPtr();

  if (vlcContextBase != 0) {
    return mpvvlc_SetupVlc(vlcContextBase);
  }
  return vlcContextBase;
}

/**
 * Address: 0x00AF63F0 (FUN_00AF63F0, _mpvvlc_InitMbaiIpic)
 *
 * What it does:
 * Seeds I-picture MBAI VLC tables (`mpvvlt_mbai_i_0` and `mpvvlt_mbai_i_1`)
 * with packed fixed and generated entries.
 */
extern "C" int mpvvlc_InitMbaiIpic()
{
  FillTableDwords(mpvvlt_mbai_i_0, 0, 8, 0x02400240u);
  WriteTableDword(mpvvlt_mbai_i_0, 8, 0x023B023Bu);
  FillTableDwords(mpvvlt_mbai_i_0, 9, 6, 0x02400240u);
  WriteTableDword(mpvvlt_mbai_i_0, 15, 0x022B022Bu);
  FillTableDwords(mpvvlt_mbai_i_0, 16, 8, 0x02400240u);

  std::size_t i0Word = 48;
  for (int i = 33; i >= 22; --i) {
    mpvvlt_mbai_i_0[i0Word++] = EncodeVlcWord(i, 0x440D);
    mpvvlt_mbai_i_0[i0Word++] = EncodeVlcWord(i, 0x040C);
  }
  for (int i = 21; i >= 16; --i) {
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 2, EncodeVlcWord(i, 0x440C));
    i0Word += 2;
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 2, EncodeVlcWord(i, 0x040B));
    i0Word += 2;
  }
  for (int i = 15; i >= 10; --i) {
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 8, EncodeVlcWord(i, 0x440A));
    i0Word += 8;
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 8, EncodeVlcWord(i, 0x0409));
    i0Word += 8;
  }
  for (int i = 9; i >= 8; --i) {
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 16, EncodeVlcWord(i, 0x4409));
    i0Word += 16;
    FillTableWords(mpvvlt_mbai_i_0, i0Word, 16, EncodeVlcWord(i, 0x0408));
    i0Word += 16;
  }

  FillTableDwords(mpvvlt_mbai_i_1, 0, 2, 0x02400240u);

  std::size_t i1Word = 4;
  for (int i = 7; i >= 6; --i) {
    mpvvlt_mbai_i_1[i1Word++] = EncodeVlcWord(i, 0x4407);
    mpvvlt_mbai_i_1[i1Word++] = EncodeVlcWord(i, 0x0406);
  }
  for (int i = 5; i >= 4; --i) {
    FillTableWords(mpvvlt_mbai_i_1, i1Word, 2, EncodeVlcWord(i, 0x4406));
    i1Word += 2;
    FillTableWords(mpvvlt_mbai_i_1, i1Word, 2, EncodeVlcWord(i, 0x0405));
    i1Word += 2;
  }
  for (int i = 3; i >= 2; --i) {
    FillTableWords(mpvvlt_mbai_i_1, i1Word, 4, EncodeVlcWord(i, 0x4405));
    i1Word += 4;
    FillTableWords(mpvvlt_mbai_i_1, i1Word, 4, EncodeVlcWord(i, 0x0404));
    i1Word += 4;
  }

  FillTableWords(mpvvlt_mbai_i_1, i1Word, 16, 0x4413u);
  i1Word += 16;
  FillTableWords(mpvvlt_mbai_i_1, i1Word, 16, 0x0412u);
  return 0x04120412;
}

/**
 * Address: 0x00AF6630 (FUN_00AF6630, _mpvvlc_InitMbaiPpic)
 *
 * What it does:
 * Seeds P-picture MBAI VLC tables (`mpvvlt_mbai_p_0` and `mpvvlt_mbai_p_1`)
 * with packed fixed and generated entries.
 */
extern "C" std::uint16_t* mpvvlc_InitMbaiPpic()
{
  FillTableDwords(mpvvlt_mbai_p_0, 0, 12, 0x02400240u);
  mpvvlt_mbai_p_0[8] = 0x023Bu;
  mpvvlt_mbai_p_0[15] = 0x022Bu;

  std::size_t p0Word = 24;
  for (int i = 33; i >= 22; --i) {
    mpvvlt_mbai_p_0[p0Word++] = EncodeVlcWord(i, 0x000B);
  }
  for (int i = 21; i >= 16; --i) {
    mpvvlt_mbai_p_0[p0Word++] = EncodeVlcWord(i, 0x000A);
    mpvvlt_mbai_p_0[p0Word++] = EncodeVlcWord(i, 0xA80B);
  }
  for (int i = 15; i >= 10; --i) {
    mpvvlt_mbai_p_0[p0Word++] = EncodeVlcWord(i, 0x0008);
    mpvvlt_mbai_p_0[p0Word++] = EncodeVlcWord(i, 0xA00B);
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 2, EncodeVlcWord(i, 0x880A));
    p0Word += 2;
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 4, EncodeVlcWord(i, 0xA809));
    p0Word += 4;
  }
  for (int i = 9; i >= 8; --i) {
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 2, EncodeVlcWord(i, 0x0007));
    p0Word += 2;
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 2, EncodeVlcWord(i, 0xA00A));
    p0Word += 2;
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 4, EncodeVlcWord(i, 0x8809));
    p0Word += 4;
    FillTableWords(mpvvlt_mbai_p_0, p0Word, 8, EncodeVlcWord(i, 0xA808));
    p0Word += 8;
  }

  FillTableDwords(mpvvlt_mbai_p_1, 0, 1, 0x02400240u);

  std::size_t p1Word = 2;
  for (int i = 7; i >= 6; --i) {
    mpvvlt_mbai_p_1[p1Word++] = EncodeVlcWord(i, 0x0005);
  }
  for (int i = 5; i >= 4; --i) {
    mpvvlt_mbai_p_1[p1Word++] = EncodeVlcWord(i, 0x0004);
    mpvvlt_mbai_p_1[p1Word++] = EncodeVlcWord(i, 0xA805);
  }
  for (int i = 3; i >= 2; --i) {
    mpvvlt_mbai_p_1[p1Word++] = EncodeVlcWord(i, 0x0003);
    mpvvlt_mbai_p_1[p1Word++] = EncodeVlcWord(i, 0x8805);
    FillTableWords(mpvvlt_mbai_p_1, p1Word, 2, EncodeVlcWord(i, 0xA804));
    p1Word += 2;
  }

  mpvvlt_mbai_p_1[p1Word++] = 0x0011u;
  mpvvlt_mbai_p_1[p1Word++] = 0x0011u;
  FillTableWords(mpvvlt_mbai_p_1, p1Word, 2, 0xA014u);
  p1Word += 2;
  FillTableWords(mpvvlt_mbai_p_1, p1Word, 4, 0x8813u);
  p1Word += 4;
  FillTableWords(mpvvlt_mbai_p_1, p1Word, 8, 0xA812u);
  p1Word += 8;
  return mpvvlt_mbai_p_1 + p1Word;
}

/**
 * Address: 0x00AF68D0 (FUN_00AF68D0, _mpvvlc_InitMbaiBpic)
 *
 * What it does:
 * Seeds B-picture MBAI VLC tables (`mpvvlt_mbai_b_0` and `mpvvlt_mbai_b_1`)
 * with packed fixed and generated entries.
 */
extern "C" std::uint16_t* mpvvlc_InitMbaiBpic()
{
  FillTableDwords(mpvvlt_mbai_b_0, 0, 12, 0x02400240u);
  mpvvlt_mbai_b_0[8] = 0x023Bu;
  mpvvlt_mbai_b_0[15] = 0x022Bu;

  std::size_t b0Word = 24;
  for (int i = 33; i >= 22; --i) {
    mpvvlt_mbai_b_0[b0Word++] = EncodeVlcWord(i, 0x000B);
  }
  for (int i = 21; i >= 16; --i) {
    const std::uint16_t value = EncodeVlcWord(i, 0x000A);
    mpvvlt_mbai_b_0[b0Word++] = value;
    mpvvlt_mbai_b_0[b0Word++] = value;
  }
  for (int i = 15; i >= 10; --i) {
    const std::uint16_t base8 = EncodeVlcWord(i, 0x0008);
    mpvvlt_mbai_b_0[b0Word++] = base8;
    mpvvlt_mbai_b_0[b0Word++] = base8;
    mpvvlt_mbai_b_0[b0Word++] = EncodeVlcWord(i, 0x900B);
    mpvvlt_mbai_b_0[b0Word++] = EncodeVlcWord(i, 0x980B);
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 2, EncodeVlcWord(i, 0xB00A));
    b0Word += 2;
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 2, EncodeVlcWord(i, 0xB80A));
    b0Word += 2;
  }
  for (int i = 9; i >= 8; --i) {
    const std::uint16_t base7 = EncodeVlcWord(i, 0x0007);
    mpvvlt_mbai_b_0[b0Word++] = base7;
    mpvvlt_mbai_b_0[b0Word++] = base7;
    mpvvlt_mbai_b_0[b0Word++] = EncodeVlcWord(i, 0xA00B);
    mpvvlt_mbai_b_0[b0Word++] = EncodeVlcWord(i, 0xA80B);
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 2, EncodeVlcWord(i, 0x900A));
    b0Word += 2;
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 2, EncodeVlcWord(i, 0x980A));
    b0Word += 2;
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 4, EncodeVlcWord(i, 0xB009));
    b0Word += 4;
    FillTableWords(mpvvlt_mbai_b_0, b0Word, 4, EncodeVlcWord(i, 0xB809));
    b0Word += 4;
  }

  FillTableDwords(mpvvlt_mbai_b_1, 0, 1, 0x02400240u);

  std::size_t b1Word = 2;
  for (int i = 7; i >= 6; --i) {
    mpvvlt_mbai_b_1[b1Word++] = EncodeVlcWord(i, 0x0005);
  }
  for (int i = 5; i >= 4; --i) {
    const std::uint16_t value = EncodeVlcWord(i, 0x0004);
    mpvvlt_mbai_b_1[b1Word++] = value;
    mpvvlt_mbai_b_1[b1Word++] = value;
  }
  for (int i = 3; i >= 2; --i) {
    const std::uint16_t value = EncodeVlcWord(i, 0x0003);
    mpvvlt_mbai_b_1[b1Word++] = value;
    mpvvlt_mbai_b_1[b1Word++] = value;
    mpvvlt_mbai_b_1[b1Word++] = EncodeVlcWord(i, 0xB005);
    mpvvlt_mbai_b_1[b1Word++] = EncodeVlcWord(i, 0xB805);
  }

  mpvvlt_mbai_b_1[b1Word++] = 0x0011u;
  mpvvlt_mbai_b_1[b1Word++] = 0x0011u;
  mpvvlt_mbai_b_1[b1Word++] = 0xA015u;
  mpvvlt_mbai_b_1[b1Word++] = 0xA815u;
  FillTableWords(mpvvlt_mbai_b_1, b1Word, 2, 0x9014u);
  b1Word += 2;
  FillTableWords(mpvvlt_mbai_b_1, b1Word, 2, 0x9814u);
  b1Word += 2;
  FillTableWords(mpvvlt_mbai_b_1, b1Word, 4, 0xB013u);
  b1Word += 4;
  FillTableWords(mpvvlt_mbai_b_1, b1Word, 4, 0xB813u);
  b1Word += 4;
  return mpvvlt_mbai_b_1 + b1Word;
}

/**
 * Address: 0x00AF63E0 (FUN_00AF63E0, _mpvvlc_InitMbai)
 *
 * What it does:
 * Initializes I/P/B-picture MBAI seed tables.
 */
extern "C" std::uint16_t* mpvvlc_InitMbai()
{
  mpvvlc_InitMbaiIpic();
  mpvvlc_InitMbaiPpic();
  return mpvvlc_InitMbaiBpic();
}

/**
 * Address: 0x00AF6CC0 (FUN_00AF6CC0, _mpvvlc_InitMotion)
 *
 * What it does:
 * Seeds motion-vector VLC tables (`mpvvlt_motion_0` and `mpvvlt_motion_1`).
 */
extern "C" int mpvvlc_InitMotion()
{
  FillTableDwords(mpvvlt_motion_0, 0, 12, 0x007F007Fu);

  std::size_t motion0Word = 24;
  for (int i = 16; i >= 11; --i) {
    mpvvlt_motion_0[motion0Word++] = EncodeSignedMotionWord(i, 0x0B);
    mpvvlt_motion_0[motion0Word++] = EncodeSignedMotionWord(-i, 0x0B);
  }
  for (int i = 10; i >= 8; --i) {
    FillTableWords(mpvvlt_motion_0, motion0Word, 2, EncodeSignedMotionWord(i, 0x0A));
    motion0Word += 2;
    FillTableWords(mpvvlt_motion_0, motion0Word, 2, EncodeSignedMotionWord(-i, 0x0A));
    motion0Word += 2;
  }
  for (int i = 7; i >= 5; --i) {
    FillTableWords(mpvvlt_motion_0, motion0Word, 8, EncodeSignedMotionWord(i, 0x08));
    motion0Word += 8;
    FillTableWords(mpvvlt_motion_0, motion0Word, 8, EncodeSignedMotionWord(-i, 0x08));
    motion0Word += 8;
  }

  FillTableDwords(mpvvlt_motion_0, motion0Word / 2, 8, 0x07040704u);
  motion0Word += 16;
  FillTableDwords(mpvvlt_motion_0, motion0Word / 2, 8, 0x07FC07FCu);

  WriteTableDword(mpvvlt_motion_1, 0, 0x007F007Fu);
  WriteTableDword(mpvvlt_motion_1, 1, 0x05FD05F3u);
  WriteTableDword(mpvvlt_motion_1, 2, 0x04020402u);
  WriteTableDword(mpvvlt_motion_1, 3, 0x04FE04FEu);
  WriteTableDword(mpvvlt_motion_1, 4, 0x03010301u);
  WriteTableDword(mpvvlt_motion_1, 5, 0x03010301u);
  WriteTableDword(mpvvlt_motion_1, 6, 0x03FF03FFu);
  WriteTableDword(mpvvlt_motion_1, 7, 0x03FF03FFu);
  FillTableDwords(mpvvlt_motion_1, 8, 8, 0x01000100u);
  return 0x01000100;
}

/**
 * Address: 0x00AF6E50 (FUN_00AF6E50, _mpvvlc_InitCbpSub1)
 *
 * What it does:
 * Seeds the first contiguous CBP VLC table segment and returns the next write
 * cursor (offset +0x80 bytes).
 */
extern "C" std::uint32_t* mpvvlc_InitCbpSub1(std::uint32_t* cbpTable)
{
  std::uint16_t* const words = reinterpret_cast<std::uint16_t*>(cbpTable);
  words[0] = 0x0000u;
  words[1] = 0x0000u;
  words[2] = 0xE709u;
  words[3] = 0xDB09u;
  words[4] = 0xFB09u;
  words[5] = 0xF709u;
  words[6] = 0xEF09u;
  words[7] = 0xDF09u;

  static constexpr std::uint32_t kTailDwords[] = {
    0xBA08BA08u, 0xB608B608u, 0xAE08AE08u, 0x9E089E08u, 0x79087908u, 0x75087508u, 0x6D086D08u,
    0x5D085D08u, 0xA608A608u, 0x9A089A08u, 0x65086508u, 0x59085908u, 0xEB08EB08u, 0xD708D708u,
    0xF308F308u, 0xCF08CF08u, 0xAA08AA08u, 0x96089608u, 0xB208B208u, 0x8E088E08u, 0x69086908u,
    0x55085508u, 0x71087108u, 0x4D084D08u, 0xE308E308u, 0xD308D308u, 0xCB08CB08u, 0xC708C708u,
  };

  for (std::size_t i = 0; i < (sizeof(kTailDwords) / sizeof(kTailDwords[0])); ++i) {
    cbpTable[4 + i] = kTailDwords[i];
  }
  return cbpTable + 32;
}

/**
 * Address: 0x00AF6F90 (FUN_00AF6F90, _mpvvlc_InitCbpSub2)
 *
 * What it does:
 * Seeds the trailing CBP VLC table segments and returns the final write cursor
 * (offset +0x380 bytes from the input cursor).
 */
extern "C" std::uint32_t* mpvvlc_InitCbpSub2(std::uint32_t* cbpCursor)
{
  FillDwords(cbpCursor, 0, 2, 0xA207A207u);
  FillDwords(cbpCursor, 2, 2, 0x92079207u);
  FillDwords(cbpCursor, 4, 2, 0x8A078A07u);
  FillDwords(cbpCursor, 6, 2, 0x86078607u);
  FillDwords(cbpCursor, 8, 2, 0x61076107u);
  FillDwords(cbpCursor, 10, 2, 0x51075107u);
  FillDwords(cbpCursor, 12, 2, 0x49074907u);
  FillDwords(cbpCursor, 14, 2, 0x45074507u);

  FillDwords(cbpCursor, 16, 4, 0xFF06FF06u);
  FillDwords(cbpCursor, 20, 4, 0xC306C306u);
  FillDwords(cbpCursor, 24, 4, 0x24062406u);
  FillDwords(cbpCursor, 28, 4, 0x18061806u);

  FillDwords(cbpCursor, 32, 8, 0xBE05BE05u);
  FillDwords(cbpCursor, 40, 8, 0x82058205u);
  FillDwords(cbpCursor, 48, 8, 0x7D057D05u);
  FillDwords(cbpCursor, 56, 8, 0x41054105u);
  FillDwords(cbpCursor, 64, 8, 0x38053805u);
  FillDwords(cbpCursor, 72, 8, 0x34053405u);
  FillDwords(cbpCursor, 80, 8, 0x2C052C05u);
  FillDwords(cbpCursor, 88, 8, 0x1C051C05u);
  FillDwords(cbpCursor, 96, 8, 0x28052805u);
  FillDwords(cbpCursor, 104, 8, 0x14051405u);
  FillDwords(cbpCursor, 112, 8, 0x30053005u);
  FillDwords(cbpCursor, 120, 8, 0x0C050C05u);

  FillDwords(cbpCursor, 128, 16, 0x20042004u);
  FillDwords(cbpCursor, 144, 16, 0x10041004u);
  FillDwords(cbpCursor, 160, 16, 0x08040804u);
  FillDwords(cbpCursor, 176, 16, 0x04040404u);
  FillDwords(cbpCursor, 192, 32, 0x3C033C03u);
  return cbpCursor + 224;
}

/**
 * Address: 0x00AF6E30 (FUN_00AF6E30, _mpvvlc_InitCbp)
 *
 * What it does:
 * Initializes the complete CBP VLC table by chaining the two contiguous seed
 * segments.
 */
extern "C" std::uint32_t* mpvvlc_InitCbp()
{
  std::uint32_t* cbpCursor = mpvvlc_InitCbpSub1(reinterpret_cast<std::uint32_t*>(mpvvlt_cbp));
  return mpvvlc_InitCbpSub2(cbpCursor);
}

/**
 * Address: 0x00AF6B90 (FUN_00AF6B90, _mpvvlc_InitMbTypePpic)
 *
 * What it does:
 * Seeds the static P-picture MB-type VLC table.
 */
extern "C" int mpvvlc_InitMbTypePpic()
{
  WriteTableDword(mpvvlt_p_mbtype, 4, 0x02020202u);
  WriteTableDword(mpvvlt_p_mbtype, 2, 0x08030803u);
  WriteTableDword(mpvvlt_p_mbtype, 5, 0x02020202u);
  WriteTableDword(mpvvlt_p_mbtype, 6, 0x02020202u);
  WriteTableDword(mpvvlt_p_mbtype, 3, 0x08030803u);
  WriteTableDword(mpvvlt_p_mbtype, 7, 0x02020202u);

  WriteTableWord(mpvvlt_p_mbtype, 0x00, 0x1106u);
  WriteTableWord(mpvvlt_p_mbtype, 0x02, 0x1205u);
  WriteTableWord(mpvvlt_p_mbtype, 0x04, 0x1A05u);
  WriteTableWord(mpvvlt_p_mbtype, 0x06, 0x0105u);

  FillTableDwords(mpvvlt_p_mbtype, 8, 8, 0x0A010A01u);
  return 0x0A010A01;
}

/**
 * Address: 0x00AF6C00 (FUN_00AF6C00, _mpvvlc_InitMbTypeBpic)
 *
 * What it does:
 * Seeds the static B-picture MB-type VLC table.
 */
extern "C" int mpvvlc_InitMbTypeBpic()
{
  WriteTableDword(mpvvlt_b_mbtype, 4, 0x08040804u);
  WriteTableDword(mpvvlt_b_mbtype, 5, 0x08040804u);
  WriteTableDword(mpvvlt_b_mbtype, 12, 0x06030603u);
  WriteTableDword(mpvvlt_b_mbtype, 8, 0x04030403u);
  WriteTableDword(mpvvlt_b_mbtype, 13, 0x06030603u);
  WriteTableDword(mpvvlt_b_mbtype, 6, 0x0A040A04u);
  WriteTableDword(mpvvlt_b_mbtype, 9, 0x04030403u);
  WriteTableDword(mpvvlt_b_mbtype, 14, 0x06030603u);
  WriteTableDword(mpvvlt_b_mbtype, 7, 0x0A040A04u);
  WriteTableDword(mpvvlt_b_mbtype, 10, 0x04030403u);
  WriteTableDword(mpvvlt_b_mbtype, 15, 0x06030603u);

  WriteTableWord(mpvvlt_b_mbtype, 0x00, 0x1F00u);
  WriteTableWord(mpvvlt_b_mbtype, 0x02, 0x1106u);
  WriteTableWord(mpvvlt_b_mbtype, 0x04, 0x1606u);
  WriteTableWord(mpvvlt_b_mbtype, 0x06, 0x1A06u);
  WriteTableDword(mpvvlt_b_mbtype, 2, 0x1E051E05u);
  WriteTableDword(mpvvlt_b_mbtype, 3, 0x01050105u);
  WriteTableDword(mpvvlt_b_mbtype, 11, 0x04030403u);

  FillTableDwords(mpvvlt_b_mbtype, 16, 8, 0x0C020C02u);
  FillTableDwords(mpvvlt_b_mbtype, 24, 8, 0x0E020E02u);
  return 0x0E020E02;
}

/**
 * Address: 0x00AF6B80 (FUN_00AF6B80, _mpvvlc_InitMbType)
 *
 * What it does:
 * Initializes both P-picture and B-picture MB-type VLC seed tables.
 */
extern "C" int mpvvlc_InitMbType()
{
  mpvvlc_InitMbTypePpic();
  return mpvvlc_InitMbTypeBpic();
}

/**
 * Address: 0x00AF71B0 (FUN_00AF71B0, _mpvvlc_InitDcSizY)
 *
 * What it does:
 * Seeds primary Y DC-size VLC table entries.
 */
extern "C" int mpvvlc_InitDcSizY()
{
  FillTableDwords(mpvvlt_y_dcsiz, 0, 8, 0x12121212u);
  FillTableDwords(mpvvlt_y_dcsiz, 8, 8, 0x22222222u);
  FillTableDwords(mpvvlt_y_dcsiz, 16, 4, 0x03030303u);
  FillTableDwords(mpvvlt_y_dcsiz, 20, 4, 0x33333333u);
  FillTableDwords(mpvvlt_y_dcsiz, 24, 4, 0x43434343u);
  FillTableDwords(mpvvlt_y_dcsiz, 28, 2, 0x54545454u);
  WriteTableDword(mpvvlt_y_dcsiz, 30, 0x65656565u);
  WriteTableWord(mpvvlt_y_dcsiz, 0x7C, 0x7676u);
  WriteTableWord(mpvvlt_y_dcsiz, 0x7E, 0x8787u);
  return 0x54545454;
}

/**
 * Address: 0x00AF7260 (FUN_00AF7260, _mpvvlc_InitDcSizC)
 *
 * What it does:
 * Seeds primary C DC-size VLC table entries.
 */
extern "C" int mpvvlc_InitDcSizC()
{
  FillTableDwords(mpvvlt_c_dcsiz, 0, 8, 0x02020202u);
  FillTableDwords(mpvvlt_c_dcsiz, 8, 8, 0x12121212u);
  FillTableDwords(mpvvlt_c_dcsiz, 16, 8, 0x22222222u);
  FillTableDwords(mpvvlt_c_dcsiz, 24, 4, 0x33333333u);
  FillTableDwords(mpvvlt_c_dcsiz, 28, 2, 0x44444444u);
  WriteTableDword(mpvvlt_c_dcsiz, 30, 0x55555555u);
  WriteTableWord(mpvvlt_c_dcsiz, 0x7C, 0x6666u);
  WriteTableByte(mpvvlt_c_dcsiz, 0x7E, 0x77u);
  WriteTableByte(mpvvlt_c_dcsiz, 0x7F, 0x88u);
  return 0x33333333;
}

/**
 * Address: 0x00AF72F0 (FUN_00AF72F0, _mpvvlc2_InitDcSizY)
 *
 * What it does:
 * Seeds secondary Y DC-size VLC table entries.
 */
extern "C" int mpvvlc2_InitDcSizY()
{
  FillTableDwords(mpvvlt2_y_dcsiz, 0, 64, 0x12121212u);
  FillTableDwords(mpvvlt2_y_dcsiz, 64, 64, 0x22222222u);
  FillTableDwords(mpvvlt2_y_dcsiz, 128, 32, 0x03030303u);
  FillTableDwords(mpvvlt2_y_dcsiz, 160, 32, 0x33333333u);
  FillTableDwords(mpvvlt2_y_dcsiz, 192, 32, 0x43434343u);
  FillTableDwords(mpvvlt2_y_dcsiz, 224, 16, 0x54545454u);
  FillTableDwords(mpvvlt2_y_dcsiz, 240, 8, 0x65656565u);
  FillTableDwords(mpvvlt2_y_dcsiz, 248, 4, 0x76767676u);
  FillTableDwords(mpvvlt2_y_dcsiz, 252, 2, 0x87878787u);
  WriteTableDword(mpvvlt2_y_dcsiz, 254, 0x98989898u);
  WriteTableWord(mpvvlt2_y_dcsiz, 0x3FC, 0xA9A9u);
  WriteTableWord(mpvvlt2_y_dcsiz, 0x3FE, 0xB9B9u);
  return 0x76767676;
}

/**
 * Address: 0x00AF73B0 (FUN_00AF73B0, _mpvvlc2_InitDcSizC)
 *
 * What it does:
 * Seeds secondary C DC-size VLC table entries.
 */
extern "C" int mpvvlc2_InitDcSizC()
{
  FillTableDwords(mpvvlt2_c_dcsiz, 0, 64, 0x02020202u);
  FillTableDwords(mpvvlt2_c_dcsiz, 64, 64, 0x12121212u);
  FillTableDwords(mpvvlt2_c_dcsiz, 128, 64, 0x22222222u);
  FillTableDwords(mpvvlt2_c_dcsiz, 192, 32, 0x33333333u);
  FillTableDwords(mpvvlt2_c_dcsiz, 224, 16, 0x44444444u);
  FillTableDwords(mpvvlt2_c_dcsiz, 240, 8, 0x55555555u);
  FillTableDwords(mpvvlt2_c_dcsiz, 248, 4, 0x66666666u);
  FillTableDwords(mpvvlt2_c_dcsiz, 252, 2, 0x77777777u);
  WriteTableDword(mpvvlt2_c_dcsiz, 254, 0x88888888u);
  WriteTableWord(mpvvlt2_c_dcsiz, 0x3FC, 0x9999u);
  WriteTableByte(mpvvlt2_c_dcsiz, 0x3FE, 0xAAu);
  WriteTableByte(mpvvlt2_c_dcsiz, 0x3FF, 0xBAu);
  return 0x66666666;
}

/**
 * Address: 0x00AF7190 (FUN_00AF7190, _mpvvlc_InitDcSiz)
 *
 * What it does:
 * Initializes primary and secondary Y/C DC-size VLC seed tables.
 */
extern "C" int mpvvlc_InitDcSiz()
{
  mpvvlc_InitDcSizY();
  mpvvlc_InitDcSizC();
  mpvvlc2_InitDcSizY();
  return mpvvlc2_InitDcSizC();
}

/**
 * Address: 0x00AF7480 (FUN_00AF7480, _mpvvlc_InitIntRunLevel)
 *
 * What it does:
 * Seeds the 8-bit run-level VLC table with fixed entries and compact value
 * runs used by MPV decode setup.
 */
extern "C" int mpvvlc_InitIntRunLevel()
{
  mpvvlt_run_level_8[0] = 0x00000000u;
  mpvvlt_run_level_8[1] = 0x00000000u;
  mpvvlt_run_level_8[2] = 0x00000000u;
  mpvvlt_run_level_8[3] = 0x00000000u;
  mpvvlt_run_level_8[4] = 0x00064040u;
  mpvvlt_run_level_8[5] = 0x00064040u;
  mpvvlt_run_level_8[6] = 0x00064040u;
  mpvvlt_run_level_8[7] = 0x00064040u;
  mpvvlt_run_level_8[8] = 0x00080202u;
  mpvvlt_run_level_8[9] = 0x00080202u;
  mpvvlt_run_level_8[10] = 0x00080109u;
  mpvvlt_run_level_8[11] = 0x00080109u;
  mpvvlt_run_level_8[12] = 0x00080400u;
  mpvvlt_run_level_8[13] = 0x00080400u;
  mpvvlt_run_level_8[14] = 0x00080108u;
  mpvvlt_run_level_8[15] = 0x00080108u;
  mpvvlt_run_level_8[16] = 0x00070107u;
  mpvvlt_run_level_8[17] = 0x00070107u;
  mpvvlt_run_level_8[18] = 0x00070107u;
  mpvvlt_run_level_8[19] = 0x00070107u;
  mpvvlt_run_level_8[20] = 0x00070106u;
  mpvvlt_run_level_8[21] = 0x00070106u;
  mpvvlt_run_level_8[22] = 0x00070106u;
  mpvvlt_run_level_8[23] = 0x00070106u;
  mpvvlt_run_level_8[24] = 0x00070201u;
  mpvvlt_run_level_8[25] = 0x00070201u;
  mpvvlt_run_level_8[26] = 0x00070201u;
  mpvvlt_run_level_8[27] = 0x00070201u;
  mpvvlt_run_level_8[28] = 0x00070105u;
  mpvvlt_run_level_8[29] = 0x00070105u;
  mpvvlt_run_level_8[30] = 0x00070105u;
  mpvvlt_run_level_8[31] = 0x00070105u;
  mpvvlt_run_level_8[32] = 0x0009010Du;
  mpvvlt_run_level_8[33] = 0x00090600u;
  mpvvlt_run_level_8[34] = 0x0009010Cu;
  mpvvlt_run_level_8[35] = 0x0009010Bu;
  mpvvlt_run_level_8[36] = 0x00090203u;
  mpvvlt_run_level_8[37] = 0x00090301u;
  mpvvlt_run_level_8[38] = 0x00090500u;
  mpvvlt_run_level_8[39] = 0x0009010Au;

  FillRunLevelVlcRange(40, 8, 0x00060300u);
  FillRunLevelVlcRange(48, 8, 0x00060104u);
  FillRunLevelVlcRange(56, 8, 0x00060103u);
  FillRunLevelVlcRange(64, 16, 0x00050200u);
  FillRunLevelVlcRange(80, 16, 0x00050102u);
  FillRunLevelVlcRange(96, 32, 0x00040101u);
  return 0x00040101;
}

/**
 * Address: 0x00AF7470 (FUN_00AF7470, _mpvvlc_InitRunLevel)
 *
 * What it does:
 * Thin run-level init thunk that forwards into the concrete 8-bit table
 * initializer.
 */
extern "C" int mpvvlc_InitRunLevel()
{
  return mpvvlc_InitIntRunLevel();
}

/**
 * Address: 0x00AF7620 (FUN_00AF7620, _mpvvlc_SetDflPtr)
 *
 * What it does:
 * Rebinds active VLC pointer lanes to their default static table roots.
 */
extern "C" void mpvvlc_SetDflPtr()
{
  mpvvlc_mbai_i_0 = mpvvlt_mbai_i_0;
  mpvvlc_mbai_i_1 = mpvvlt_mbai_i_1;
  mpvvlc_mbai_p_0 = mpvvlt_mbai_p_0;
  mpvvlc_mbai_p_1 = mpvvlt_mbai_p_1;
  mpvvlc_mbai_b_0 = mpvvlt_mbai_b_0;
  mpvvlc_mbai_b_1 = mpvvlt_mbai_b_1;
  mpvvlc_p_mbtype = mpvvlt_p_mbtype;
  mpvvlc_b_mbtype = mpvvlt_b_mbtype;
  mpvvlc_motion_0 = mpvvlt_motion_0;
  mpvvlc_motion_1 = mpvvlt_motion_1;
  mpvvlc_cbp = mpvvlt_cbp;
  mpvvlc_y_dcsiz = mpvvlt_y_dcsiz;
  mpvvlc_c_dcsiz = mpvvlt_c_dcsiz;
  mpvvlc2_y_dcsiz = mpvvlt2_y_dcsiz;
  mpvvlc2_c_dcsiz = mpvvlt2_c_dcsiz;

  mpvvlc_run_level_0c = mpvvlt_run_level_0c;
  mpvvlc_run_level_0b = mpvvlt_run_level_0b;
  mpvvlc_run_level_0a = mpvvlt_run_level_0a;
  mpvvlc_run_level_1 = mpvvlt_run_level_1;
  mpvvlc_run_level_2 = mpvvlt_run_level_2;
  mpvvlc_run_level_4 = mpvvlt_run_level_4;
  mpvvlc_run_level_8 = mpvvlt_run_level_8;
}

/**
 * Address: 0x00AF7730 (FUN_00AF7730, _mpvvlc_SetVlcRunLevel)
 *
 * What it does:
 * Carves run-level VLC lanes inside the runtime setup arena and copies static
 * defaults into each lane.
 */
extern "C" int mpvvlc_SetVlcRunLevel(const int runLevelStateBase)
{
  int writeCursor = runLevelStateBase - 0x200;
  mpvvlc_run_level_8 = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_8, 0x80);

  writeCursor -= 0x10;
  mpvvlc_run_level_4 = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_4, 4);

  writeCursor -= 0x20;
  mpvvlc_run_level_2 = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_2, 8);

  writeCursor -= 0x20;
  mpvvlc_run_level_1 = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_1, 8);

  writeCursor -= 0x20;
  mpvvlc_run_level_0a = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_0a, 8);

  writeCursor -= 0x20;
  mpvvlc_run_level_0b = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_0b, 8);

  writeCursor -= 0x20;
  mpvvlc_run_level_0c = reinterpret_cast<std::uint32_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_run_level_0c, 8);
  return writeCursor;
}

/**
 * Address: 0x00AF77E0 (FUN_00AF77E0, _mpvvlc_SetVlcDcSiz)
 *
 * What it does:
 * Allocates Y/C DC-size VLC lanes in the setup arena and copies their default
 * decode tables.
 */
extern "C" int mpvvlc_SetVlcDcSiz(const int runLevelState)
{
  int writeCursor = runLevelState - 0x80;
  mpvvlc_y_dcsiz = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_y_dcsiz, 0x20);

  writeCursor -= 0x80;
  mpvvlc_c_dcsiz = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_c_dcsiz, 0x20);
  return writeCursor;
}

/**
 * Address: 0x00AF7820 (FUN_00AF7820, _mpvvlc_SetVlcMotion)
 *
 * What it does:
 * Writes motion-vector VLC tables into the setup arena and returns the next
 * free cursor for downstream setup lanes.
 */
extern "C" int mpvvlc_SetVlcMotion(const int runLevelState)
{
  int writeCursor = runLevelState - 0x100;
  mpvvlc_motion_0 = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_motion_0, 0x40);

  writeCursor -= 0x40;
  mpvvlc_motion_1 = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_motion_1, 0x10);
  return writeCursor;
}

/**
 * Address: 0x00AF7860 (FUN_00AF7860, _mpvvlc_SetVlcMbType)
 *
 * What it does:
 * Allocates and seeds P/B macroblock-type VLC tables, returning the remaining
 * setup cursor after both tables are copied.
 */
extern "C" int mpvvlc_SetVlcMbType(const int runLevelState)
{
  int writeCursor = runLevelState - 0x40;
  mpvvlc_p_mbtype = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_p_mbtype, 0x10);

  writeCursor -= 0x80;
  mpvvlc_b_mbtype = reinterpret_cast<const std::uint16_t*>(AddressToMutablePointer(writeCursor));
  CopyDwordsToAddress(writeCursor, mpvvlt_b_mbtype, 0x20);
  return writeCursor;
}

/**
 * Address: 0x00AF7700 (FUN_00AF7700, _mpvvlc_SetupVlc)
 *
 * What it does:
 * Builds VLC runtime state by chaining run-level, DC-size, motion, and
 * macroblock-type setup lanes.
 */
extern "C" int mpvvlc_SetupVlc(const int vlcContextBase)
{
  int runLevelState = mpvvlc_SetVlcRunLevel(vlcContextBase + 0x5B0);
  runLevelState = mpvvlc_SetVlcDcSiz(runLevelState);
  runLevelState = mpvvlc_SetVlcMotion(runLevelState);
  return mpvvlc_SetVlcMbType(runLevelState);
}

namespace moho::movie
{
  /**
   * Address: 0x00C0CC70 (FUN_00C0CC70)
   *
   * What it does:
   * Computes luma/chroma byte deltas for the current MB row/column against a
   * macroblock plane-offset descriptor.
   */
  int MPVUMC_GetMacroblockPlaneOffsets(
    const MPVDecoderContextPrefix* context, const MPVMacroblockOffsets& blockOffsets, MPVSpatialDelta& outDelta
  )
  {
    const int macroblockRowTimes16 = 16 * context->macroblockRow;
    const int macroblockColumnTimes8 = 8 * context->macroblockColumn;

    outDelta.luma = macroblockColumnTimes8 + 8 * context->macroblockRow * static_cast<int>(blockOffsets.lumaStride);
    outDelta.chroma = macroblockRowTimes16 * static_cast<int>(blockOffsets.chromaStride) + 2 * macroblockColumnTimes8;

    return macroblockRowTimes16;
  }

  /**
   * Address: 0x00C0C080 (FUN_00C0C080)
   *
   * LUT-based block sample copy helper.
   *
   * What it does:
   * Copies six 8x8 blocks from source-address LUT entries into destination
   * targets, adding the current luma base address bias.
   */
  int MPVUMC_CopyIntraBlocks(const std::int16_t* sourceAddressLut, MPVCopyDestinationSet& destinations, int lumaBaseAddress)
  {
    int remainingBlocks = 6;
    for (MPVBlockWriteTarget& block : destinations.blocks) {
      WriteEightRows(
        block,
        [&](std::uint8_t* dst)
        {
          dst[0] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[0]));
          dst[1] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[1]));
          dst[2] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[2]));
          dst[3] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[3]));
          dst[4] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[4]));
          dst[5] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[5]));
          dst[6] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[6]));
          dst[7] = ReadAddressedSample(lumaBaseAddress, static_cast<int>(sourceAddressLut[7]));
          sourceAddressLut += 8;
        }
      );
      --remainingBlocks;
    }

    return remainingBlocks;
  }

  /**
   * Address: 0x00C0CA20 (FUN_00C0CA20)
   *
   * What it does:
   * Copies one macroblock prediction span between offset descriptors (luma and
   * packed chroma lanes) using the provided MB spatial delta.
   */
  int MPVUMC_CopyPredictionSpan(
    const MPVSpatialDelta& mbDelta, const MPVMacroblockOffsets& sourceOffsets, const MPVMacroblockOffsets& destinationOffsets
  )
  {
    const int lumaStride = static_cast<int>(destinationOffsets.lumaStride);
    const std::uint8_t* const srcLuma0 = AddressToPointer(mbDelta.luma + sourceOffsets.lumaOffset);
    const std::uint8_t* const srcLuma1 = AddressToPointer(mbDelta.luma + sourceOffsets.chromaUOffset);
    std::uint8_t* const dstLuma0 = AddressToMutablePointer(mbDelta.luma + destinationOffsets.lumaOffset);
    std::uint8_t* const dstLuma1 = AddressToMutablePointer(mbDelta.luma + destinationOffsets.chromaUOffset);

    for (int row = 0; row < 16; ++row) {
      const int rowOffset = row * lumaStride;
      std::memcpy(dstLuma0 + rowOffset, srcLuma0 + rowOffset, 8);
      std::memcpy(dstLuma1 + rowOffset, srcLuma1 + rowOffset, 8);
    }

    const int chromaStride = static_cast<int>(destinationOffsets.chromaStride);
    const std::uint8_t* const srcChroma = AddressToPointer(mbDelta.chroma + sourceOffsets.chromaVOffset);
    std::uint8_t* const dstChroma = AddressToMutablePointer(mbDelta.chroma + destinationOffsets.chromaVOffset);

    for (int row = 0; row < 8; ++row) {
      const int rowOffset = row * chromaStride;
      std::memcpy(dstChroma + rowOffset, srcChroma + rowOffset, 16);
    }

    return chromaStride;
  }

  /**
   * Address: 0x00C0E370 (FUN_00C0E370)
   *
   * What it does:
   * Scalar 8x8 copy kernel used by interpolation dispatch tables.
   */
  int MPVKernel_Copy8x8(MPVPredictionKernelState* kernelState)
  {
    return RunKernelFromPrimarySource(
      kernelState,
      [](const std::uint8_t* source, const int column)
      {
        return source[column];
      }
    );
  }

  /**
   * Address: 0x00C0E780 (FUN_00C0E780)
   *
   * What it does:
   * Scalar 8x8 kernel: rounded average of primary/secondary source lanes.
   */
  int MPVKernel_AvgPrimarySecondary(MPVPredictionKernelState* kernelState)
  {
    return RunKernelFromPrimarySecondarySources(
      kernelState,
      [](const std::uint8_t* sourcePrimary, const std::uint8_t* sourceSecondary, const int column)
      {
        return (static_cast<int>(sourcePrimary[column]) + static_cast<int>(sourceSecondary[column]) + 1) >> 1;
      }
    );
  }

  /**
   * Address: 0x00C0E850 (FUN_00C0E850)
   *
   * What it does:
   * Scalar 8x8 kernel: rounded horizontal average on primary source lane.
   */
  int MPVKernel_AvgHorizontal(MPVPredictionKernelState* kernelState)
  {
    return RunKernelFromPrimarySource(
      kernelState,
      [](const std::uint8_t* source, const int column)
      {
        return (static_cast<int>(source[column]) + static_cast<int>(source[column + 1]) + 1) >> 1;
      }
    );
  }

  /**
   * Address: 0x00C0E910 (FUN_00C0E910)
   *
   * What it does:
   * Scalar 8x8 kernel: quarter-sample blend from 2x2 primary/secondary pairs.
   */
  int MPVKernel_AvgHorizontalAndSecondary(MPVPredictionKernelState* kernelState)
  {
    return RunKernelFromPrimarySecondarySources(
      kernelState,
      [](const std::uint8_t* sourcePrimary, const std::uint8_t* sourceSecondary, const int column)
      {
        const int sum =
          static_cast<int>(sourcePrimary[column]) + static_cast<int>(sourcePrimary[column + 1]) +
          static_cast<int>(sourceSecondary[column]) + static_cast<int>(sourceSecondary[column + 1]);
        return (sum + 2) >> 2;
      }
    );
  }

  /**
   * Address: 0x00C0EA50 (FUN_00C0EA50)
   *
   * What it does:
   * SSE/MMX lane variant of primary/secondary rounded-average kernel.
   */
  int MPVKernel_AvgPrimarySecondarySse(MPVPredictionKernelState* kernelState)
  {
    return MPVKernel_AvgPrimarySecondary(kernelState);
  }

  /**
   * Address: 0x00C0EB00 (FUN_00C0EB00)
   *
   * What it does:
   * SSE/MMX lane variant of horizontal rounded-average kernel.
   */
  int MPVKernel_AvgHorizontalSse(MPVPredictionKernelState* kernelState)
  {
    return MPVKernel_AvgHorizontal(kernelState);
  }

  /**
   * Address: 0x00C0EBA0 (FUN_00C0EBA0)
   *
   * What it does:
   * SSE/MMX lane variant of 8x8 copy kernel.
   */
  int MPVKernel_Copy8x8Sse(MPVPredictionKernelState* kernelState)
  {
    return MPVKernel_Copy8x8(kernelState);
  }

  /**
   * Address: 0x00C0EC20 (FUN_00C0EC20)
   *
   * What it does:
   * MMX lane variant of primary/secondary rounded-average kernel.
   */
  int MPVKernel_AvgPrimarySecondaryMmx(MPVPredictionKernelState* kernelState)
  {
    return MPVKernel_AvgPrimarySecondary(kernelState);
  }

  /**
   * Address: 0x00C0EDC0 (FUN_00C0EDC0)
   *
   * What it does:
   * MMX lane variant of horizontal rounded-average kernel.
   */
  int MPVKernel_AvgHorizontalMmx(MPVPredictionKernelState* kernelState)
  {
    return MPVKernel_AvgHorizontal(kernelState);
  }

  /**
   * Address: 0x00C0C390 (FUN_00C0C390)
   *
   * What it does:
   * Builds prediction pointers for one reference lane using motion deltas and
   * dispatches interpolation kernels for 6 block destinations.
   */
  int form_prediction(
    MPVDecoderContextPrefix* context,
    int predictionWriteBaseAddress,
    MPVSpatialDelta* outDelta,
    const MPVMacroblockOffsets* blockOffsets,
    const MPVPredictionVectorSet* motionVector
  )
  {
    InitializeMpvInterpolationDispatch();
    MPVUMC_GetMacroblockPlaneOffsets(context, *blockOffsets, *outDelta);

    int motionX = motionVector->horizontalDelta;
    int motionY = motionVector->verticalDelta;

    const int minHorizontal = -32 * context->macroblockColumn;
    const int maxHorizontal = 32 * (context->macroblocksPerRow - context->macroblockColumn) - 32;
    if (motionX < minHorizontal) {
      motionX = minHorizontal;
      ++AsRuntimeStats(context)->motionClampCounter;
    } else if (motionX > maxHorizontal) {
      motionX = maxHorizontal;
      ++AsRuntimeStats(context)->motionClampCounter;
    }

    const int minVertical = -32 * context->macroblockRow;
    const int maxVertical = 32 * (context->macroblockRowsCount - context->macroblockRow) - 32;
    if (motionY < minVertical) {
      motionY = minVertical;
      ++AsRuntimeStats(context)->motionClampCounter;
    } else if (motionY > maxVertical) {
      motionY = maxVertical;
      ++AsRuntimeStats(context)->motionClampCounter;
    }

    const std::uint32_t interpolationParity = static_cast<std::uint32_t>(context->interpolationParity);
    const std::uint32_t fullKernelIndex = (static_cast<std::uint32_t>(motionX) & 1u) + (((static_cast<std::uint32_t>(motionY) & 1u) + interpolationParity * 2u) * 2u);
    const std::uint32_t halfKernelIndex = static_cast<std::uint32_t>(((motionX / 2) & 1) + ((((motionY / 2) & 1) + static_cast<int>(interpolationParity) * 2) * 2));

    const MPVInterpolationKernelFn fullKernel = g_mpvInterpolationDispatch[fullKernelIndex];
    const MPVInterpolationKernelFn halfKernel = g_mpvInterpolationDispatch[halfKernelIndex];

    const int halfHorizontal = motionX / 2;
    const int halfVertical = motionY / 2;
    const int halfHorizontalParity = halfHorizontal & 1;
    const int halfVerticalParity = halfVertical & 1;

    const int lumaSourceBase = outDelta->luma + (halfHorizontal >> 1) + (halfVertical >> 1) * static_cast<int>(blockOffsets->lumaStride);
    const int chromaSourceBase =
      outDelta->chroma + (motionX >> 1) + (motionY >> 1) * static_cast<int>(blockOffsets->chromaStride);

    auto* const kernelState = AsPredictionKernelState(context);
    const int lumaParityBias = halfHorizontalParity & static_cast<int>(interpolationParity);
    const int chromaParityBias = (motionX & 1) & static_cast<int>(interpolationParity);

    kernelState->destinationStride = static_cast<int>(blockOffsets->lumaStride);
    kernelState->destinationBlockBase = predictionWriteBaseAddress;
    kernelState->sourcePrimary = blockOffsets->lumaOffset + lumaSourceBase;
    kernelState->sourceSecondary = kernelState->sourcePrimary + lumaParityBias + static_cast<int>(blockOffsets->lumaStride);
    halfKernel(kernelState);

    kernelState->destinationBlockBase = predictionWriteBaseAddress + 0x40;
    kernelState->sourcePrimary = blockOffsets->chromaUOffset + lumaSourceBase;
    kernelState->sourceSecondary = kernelState->sourcePrimary + lumaParityBias + static_cast<int>(blockOffsets->lumaStride);
    halfKernel(kernelState);

    kernelState->destinationStride = static_cast<int>(blockOffsets->chromaStride);
    kernelState->destinationBlockBase = predictionWriteBaseAddress + 0x80;
    kernelState->sourcePrimary = blockOffsets->chromaVOffset + chromaSourceBase;
    kernelState->sourceSecondary = kernelState->sourcePrimary + chromaParityBias + static_cast<int>(blockOffsets->chromaStride);
    fullKernel(kernelState);

    kernelState->destinationBlockBase = predictionWriteBaseAddress + 0xC0;
    kernelState->sourcePrimary += 8;
    kernelState->sourceSecondary += 8;
    fullKernel(kernelState);

    kernelState->destinationBlockBase = predictionWriteBaseAddress + 0x100;
    kernelState->sourcePrimary += 8 * static_cast<int>(blockOffsets->chromaStride) - 8;
    kernelState->sourceSecondary += 8 * static_cast<int>(blockOffsets->chromaStride) - 8;
    fullKernel(kernelState);

    kernelState->destinationBlockBase = predictionWriteBaseAddress + 0x140;
    kernelState->sourcePrimary += 8;
    kernelState->sourceSecondary += 8;
    return fullKernel(kernelState);
  }

  /**
   * Address: 0x00C0C1C0 (FUN_00C0C1C0)
   *
   * What it does:
   * Recovers forward-predicted MB samples then writes frame420 blocks.
   */
  int MPVUMC_Forward(MPVDecoderContextPrefix* context)
  {
    MPVSpatialDelta delta{};
    form_prediction(
      context,
      PointerToAddress(context->blockSources.forwardSamples),
      &delta,
      &context->forwardOffsets,
      &context->forwardPredictionVector
    );
    ConfigureCopyTargetPlanes(context, delta);
    return addBlocksFrame420_also(&context->blockSources, &context->copyTargets, context->predictionSignState);
  }

  /**
   * Address: 0x00C0C250 (FUN_00C0C250)
   *
   * What it does:
   * Recovers backward-predicted MB samples then writes frame420 blocks.
   */
  int MPVUMC_Backward(MPVDecoderContextPrefix* context)
  {
    MPVSpatialDelta delta{};
    form_prediction(
      context,
      PointerToAddress(context->blockSources.forwardSamples),
      &delta,
      &context->backwardOffsets,
      &context->backwardPredictionVector
    );
    ConfigureCopyTargetPlanes(context, delta);
    return addBlocksFrame420_also(&context->blockSources, &context->copyTargets, context->predictionSignState);
  }

  /**
   * Address: 0x00C0C2E0 (FUN_00C0C2E0)
   *
   * What it does:
   * Recovers forward+backward MB samples and writes bi-directional frame420
   * blend blocks.
   */
  int MPVUMC_BiDirect(MPVDecoderContextPrefix* context)
  {
    MPVSpatialDelta delta{};
    form_prediction(
      context,
      PointerToAddress(context->blockSources.forwardSamples),
      &delta,
      &context->forwardOffsets,
      &context->forwardPredictionVector
    );
    form_prediction(
      context,
      PointerToAddress(context->blockSources.backwardSamples),
      &delta,
      &context->backwardOffsets,
      &context->backwardPredictionVector
    );
    ConfigureCopyTargetPlanes(context, delta);
    return addBlocksFrame420(&context->blockSources, &context->copyTargets, context->predictionSignState);
  }

  /**
   * Address: 0x00C0C000 (FUN_00C0C000)
   *
   * MPV decoder intra macroblock path.
   *
   * What it does:
   * Computes destination plane pointers for the current MB and writes the six
   * intra 8x8 blocks through the LUT-based luma copy path.
   */
  int MPVUMC_Intra(MPVDecoderContextPrefix* context)
  {
    MPVSpatialDelta delta{};
    MPVUMC_GetMacroblockPlaneOffsets(context, context->forwardOffsets, delta);
    ConfigureCopyTargetPlanes(context, delta);
    return MPVUMC_CopyIntraBlocks(context->intraCopyAddressLut, context->copyTargets, context->lumaBaseAddress);
  }

  /**
   * Address: 0x00C0C5C0 (FUN_00C0C5C0)
   *
   * What it does:
   * Writes six frame-420 prediction blocks from one predictor lane, using
   * either indexed fetches or direct byte copies based on sign-state.
   */
  int addBlocksFrame420_also(MPVBlockSourceSet* source, MPVCopyDestinationSet* destinations, int predictionSignBits)
  {
    int remainingBlocks = 6;
    std::int16_t* sampleAddressLut = source->sampleAddressLut;
    std::uint8_t* forwardSamples = source->forwardSamples;

    for (MPVBlockWriteTarget& block : destinations->blocks) {
      if (predictionSignBits < 0) {
        WriteEightRows(
          block,
          [&](std::uint8_t* dst)
          {
            dst[0] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[0]) + static_cast<int>(forwardSamples[0])
            );
            dst[1] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[1]) + static_cast<int>(forwardSamples[1])
            );
            dst[2] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[2]) + static_cast<int>(forwardSamples[2])
            );
            dst[3] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[3]) + static_cast<int>(forwardSamples[3])
            );
            dst[4] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[4]) + static_cast<int>(forwardSamples[4])
            );
            dst[5] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[5]) + static_cast<int>(forwardSamples[5])
            );
            dst[6] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[6]) + static_cast<int>(forwardSamples[6])
            );
            dst[7] = ReadAddressedSample(
              source->sampleBaseBias, static_cast<int>(sampleAddressLut[7]) + static_cast<int>(forwardSamples[7])
            );

            sampleAddressLut += 8;
            forwardSamples += 8;
          }
        );
      } else {
        sampleAddressLut += 64;
        WriteEightRows(
          block,
          [&](std::uint8_t* dst)
          {
            std::memcpy(dst, forwardSamples, 8);
            forwardSamples += 8;
          }
        );
      }

      predictionSignBits *= 2;
      --remainingBlocks;
    }

    return remainingBlocks;
  }

  /**
   * Address: 0x00C0C760 (FUN_00C0C760)
   *
   * What it does:
   * Writes six frame-420 prediction blocks by averaging forward/backward
   * predictor lanes, with indexed or direct byte-path based on sign-state.
   */
  int addBlocksFrame420(MPVBlockSourceSet* source, MPVCopyDestinationSet* destinations, int predictionSignBits)
  {
    int remainingBlocks = 6;
    std::int16_t* sampleAddressLut = source->sampleAddressLut;
    std::uint8_t* forwardSamples = source->forwardSamples;
    std::uint8_t* backwardSamples = source->backwardSamples;

    for (MPVBlockWriteTarget& block : destinations->blocks) {
      if (predictionSignBits < 0) {
        WriteEightRows(
          block,
          [&](std::uint8_t* dst)
          {
            dst[0] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[0]) + ((static_cast<int>(forwardSamples[0]) + static_cast<int>(backwardSamples[0]) + 1) >> 1)
            );
            dst[1] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[1]) + ((static_cast<int>(forwardSamples[1]) + static_cast<int>(backwardSamples[1]) + 1) >> 1)
            );
            dst[2] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[2]) + ((static_cast<int>(forwardSamples[2]) + static_cast<int>(backwardSamples[2]) + 1) >> 1)
            );
            dst[3] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[3]) + ((static_cast<int>(forwardSamples[3]) + static_cast<int>(backwardSamples[3]) + 1) >> 1)
            );
            dst[4] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[4]) + ((static_cast<int>(forwardSamples[4]) + static_cast<int>(backwardSamples[4]) + 1) >> 1)
            );
            dst[5] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[5]) + ((static_cast<int>(forwardSamples[5]) + static_cast<int>(backwardSamples[5]) + 1) >> 1)
            );
            dst[6] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[6]) + ((static_cast<int>(forwardSamples[6]) + static_cast<int>(backwardSamples[6]) + 1) >> 1)
            );
            dst[7] = ReadAddressedSample(
              source->sampleBaseBias,
              static_cast<int>(sampleAddressLut[7]) + ((static_cast<int>(forwardSamples[7]) + static_cast<int>(backwardSamples[7]) + 1) >> 1)
            );

            sampleAddressLut += 8;
            forwardSamples += 8;
            backwardSamples += 8;
          }
        );
      } else {
        sampleAddressLut += 64;
        WriteEightRows(
          block,
          [&](std::uint8_t* dst)
          {
            dst[0] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[0]) + static_cast<int>(backwardSamples[0]) + 1) >> 1);
            dst[1] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[1]) + static_cast<int>(backwardSamples[1]) + 1) >> 1);
            dst[2] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[2]) + static_cast<int>(backwardSamples[2]) + 1) >> 1);
            dst[3] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[3]) + static_cast<int>(backwardSamples[3]) + 1) >> 1);
            dst[4] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[4]) + static_cast<int>(backwardSamples[4]) + 1) >> 1);
            dst[5] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[5]) + static_cast<int>(backwardSamples[5]) + 1) >> 1);
            dst[6] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[6]) + static_cast<int>(backwardSamples[6]) + 1) >> 1);
            dst[7] = static_cast<std::uint8_t>((static_cast<int>(forwardSamples[7]) + static_cast<int>(backwardSamples[7]) + 1) >> 1);
            forwardSamples += 8;
            backwardSamples += 8;
          }
        );
      }

      predictionSignBits *= 2;
      --remainingBlocks;
    }

    return remainingBlocks;
  }

  /**
   * Address: 0x00C0C9B0 (FUN_00C0C9B0)
   *
   * What it does:
   * Rewinds MB address by skip count and copies forward prediction lanes into
   * backward lanes for each skipped P-picture MB.
   */
  int MPVUMC_PpicSkipped(MPVDecoderContextPrefix* context, int skippedMacroblockCount)
  {
    const int previousLinearIndex = context->macroblockLinearIndex;
    mpvumc_SubMbadr(context, skippedMacroblockCount);

    while (context->macroblockLinearIndex < previousLinearIndex) {
      MPVSpatialDelta mbDelta{};
      MPVUMC_GetMacroblockPlaneOffsets(context, context->forwardOffsets, mbDelta);
      MPVUMC_CopyPredictionSpan(mbDelta, context->forwardOffsets, context->backwardOffsets);
      mpvumc_IncreMbadr(context);
    }

    return context->macroblockLinearIndex;
  }

  /**
   * Address: 0x00C0CC20 (FUN_00C0CC20)
   *
   * What it does:
   * Rewinds MB address by skip count and decodes B-picture skipped MBs through
   * the configured callback until the prior linear MB index is reached.
   */
  int MPVUMC_BpicSkipped(MPVDecoderContextPrefix* context, int skippedMacroblockCount)
  {
    const MPVDecodeMacroblockFn decodeMacroblock = context->decodeSkippedBpicMacroblock;
    const int previousLinearIndex = context->macroblockLinearIndex;

    context->predictionSignState = 0;
    mpvumc_SubMbadr(context, skippedMacroblockCount);
    while (context->macroblockLinearIndex < previousLinearIndex) {
      decodeMacroblock(context);
      mpvumc_IncreMbadr(context);
    }

    return context->macroblockLinearIndex;
  }

  /**
   * Address: 0x00C0CCB0 (FUN_00C0CCB0)
   *
   * What it does:
   * Decrements MB address by a skip amount and wraps row/column indices when
   * the column crosses the left boundary.
   */
  MPVDecoderContextPrefix* mpvumc_SubMbadr(MPVDecoderContextPrefix* context, int decrement)
  {
    int nextColumn = context->macroblockColumn + (1 - decrement);
    context->macroblockLinearIndex += (1 - decrement);
    context->macroblockColumn = nextColumn;

    if (nextColumn < 0) {
      int row = context->macroblockRow;
      do {
        nextColumn += context->macroblocksPerRow;
        --row;
      } while (nextColumn < 0);

      context->macroblockColumn = nextColumn;
      context->macroblockRow = row;
    }

    return context;
  }

  /**
   * Address: 0x00C0CD10 (FUN_00C0CD10)
   *
   * What it does:
   * Increments MB address by one and wraps row/column indices when the column
   * reaches row width.
   */
  MPVDecoderContextPrefix* mpvumc_IncreMbadr(MPVDecoderContextPrefix* context)
  {
    const int nextColumn = context->macroblockColumn + 1;
    context->macroblockColumn = nextColumn;

    if (nextColumn >= context->macroblocksPerRow) {
      context->macroblockColumn = 0;
      ++context->macroblockRow;
    }

    ++context->macroblockLinearIndex;
    return context;
  }

  /**
   * Address: 0x00C0CD50 (FUN_00C0CD50)
   *
   * What it does:
   * Decodes I-picture macroblocks for the current slice chunk and dispatches
   * intra decode callbacks for each accepted macroblock.
   */
  int MPVDEC_DecIpicMb(MPVDecoderScanContext* context, MPVSjStream* stream)
  {
    SjRequestChunk(stream, context->activeChunk);
    LoadBitstreamFromChunk(context->activeChunk, context->sliceBitAlignment, context->bitstreamState);

    while (true) {
      if (PeekWindowBits(context->bitstreamState, 9) == 0) {
        break;
      }

      const int previousLinearIndex = context->macroblockLinearIndex;
      int mbaiCode = 0;
      std::int16_t mbaiEntry = 0;
      while (true) {
        std::uint32_t mbaiIndex = PeekWindowBits(context->bitstreamState, 20);
        const std::uint16_t* mbaiTable = mpvvlc_mbai_i_0;
        if ((mbaiIndex & 0xFFFFFF00u) != 0) {
          mbaiTable = mpvvlc_mbai_i_1;
          mbaiIndex >>= 6;
        }

        mbaiEntry = static_cast<std::int16_t>(mbaiTable[mbaiIndex]);
        const int mbaiConsume = static_cast<int>(mbaiEntry) & 0x0F;
        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          mbaiConsume
        );

        mbaiCode = static_cast<int>(static_cast<std::uint8_t>(mbaiEntry >> 2)) >> 2;
        if (mbaiCode == 34) {
          continue;
        }

        if (mbaiCode == 35) {
          context->macroblockLinearIndex += 33;
          continue;
        }

        break;
      }

      if (mbaiCode == 36) {
        break;
      }

      context->macroblockLinearIndex += mbaiCode;
      context->macroblockTypeFlags = static_cast<int>(static_cast<unsigned int>(mbaiEntry) >> 10);
      if (context->macroblockLinearIndex > context->macroblockLinearLimit) {
        break;
      }

      const int macroblockAdvance = context->macroblockLinearIndex - previousLinearIndex;
      context->macroblockColumn += macroblockAdvance;
      while (context->macroblockColumn >= context->macroblocksPerRow) {
        context->macroblockColumn -= context->macroblocksPerRow;
        ++context->macroblockRow;
      }

      if (macroblockAdvance == -2) {
        break;
      }

      if ((context->macroblockTypeFlags & 0x10) != 0) {
        context->decodeBitWindow = static_cast<int>(
          ConsumeAndExtractBits(
            context->bitstreamState.bitWindowPrimary,
            context->bitstreamState.bitWindowSecondary,
            context->bitstreamState.bitCount,
            context->bitstreamState.byteCursor,
            5
          )
        );
      }

      if (context->macroblockLinearIndex != context->lastDecodedMacroblockIndex + 1) {
        context->macroblockDiscontinuityHandler(context);
      }

      context->decodeIntraMacroblock(context);
      context->decodePostIntraMacroblock(context);

      if (context->recoverNeededFlag != 0) {
        break;
      }

      context->lastDecodedMacroblockIndex = context->macroblockLinearIndex;
      --context->serviceCountdown;
      if (context->serviceCountdown <= 0) {
        context->serviceCountdown = context->serviceReloadInterval;
        context->serviceCallback(context->serviceCallbackToken);
      }

      const int refillSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, true);
      if (context->activeChunk.size - refillSplitOffset <= 0x800) {
        MPVSjChunk tailChunk{};
        SJ_SplitChunk(&context->activeChunk, refillSplitOffset, &context->activeChunk, &tailChunk);
        SjReleaseHeadChunk(stream, context->activeChunk);
        SjSubmitTailChunk(stream, tailChunk);
        SjRequestChunk(stream, context->activeChunk);

        const int preservedBitAlignment = context->bitstreamState.bitCount & 7;
        LoadBitstreamFromChunk(context->activeChunk, preservedBitAlignment, context->bitstreamState);
      }
    }

    MPVSjChunk tailChunk{};
    const int finalSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, false);
    SJ_SplitChunk(&context->activeChunk, finalSplitOffset, &context->activeChunk, &tailChunk);
    SjReleaseHeadChunk(stream, context->activeChunk);
    SjSubmitTailChunk(stream, tailChunk);
    return MPV_GoNextDelimSj(stream);
  }

  /**
   * Address: 0x00C0D1D0 (FUN_00C0D1D0)
   *
   * What it does:
   * Decodes P-picture macroblocks for the current slice chunk, including
   * skip-run handling, forward motion decode, and CBP dispatch.
   */
  int MPVDEC_DecPpicMb(MPVDecoderScanContext* context, MPVSjStream* stream)
  {
    int isFirstMacroblock = 1;
    SjRequestChunk(stream, context->activeChunk);
    LoadBitstreamFromChunk(context->activeChunk, context->sliceBitAlignment, context->bitstreamState);

    while (true) {
      if (PeekWindowBits(context->bitstreamState, 9) == 0) {
        break;
      }

      const int previousLinearIndex = context->macroblockLinearIndex;
      int mbaiCode = 0;
      std::int16_t mbaiEntry = 0;
      while (true) {
        std::uint32_t mbaiIndex = PeekWindowBits(context->bitstreamState, 21);
        const std::uint16_t* mbaiTable = mpvvlc_mbai_p_0;
        if ((mbaiIndex & 0xFFFFFF80u) != 0) {
          mbaiTable = mpvvlc_mbai_p_1;
          mbaiIndex >>= 6;
        }

        mbaiEntry = static_cast<std::int16_t>(mbaiTable[mbaiIndex]);
        const int mbaiConsume = static_cast<int>(mbaiEntry) & 0x0F;
        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          mbaiConsume
        );

        mbaiCode = static_cast<int>(static_cast<std::uint8_t>(mbaiEntry >> 2)) >> 2;
        if (mbaiCode == 34) {
          continue;
        }

        if (mbaiCode == 35) {
          context->macroblockLinearIndex += 33;
          continue;
        }

        break;
      }

      if (mbaiCode == 36) {
        break;
      }

      context->macroblockLinearIndex += mbaiCode;
      context->macroblockTypeFlags = static_cast<int>(static_cast<unsigned int>(mbaiEntry) >> 10);
      if (context->macroblockLinearIndex > context->macroblockLinearLimit) {
        break;
      }

      const int macroblockAdvance = context->macroblockLinearIndex - previousLinearIndex;
      context->macroblockColumn += macroblockAdvance;
      while (context->macroblockColumn >= context->macroblocksPerRow) {
        context->macroblockColumn -= context->macroblocksPerRow;
        ++context->macroblockRow;
      }

      if (macroblockAdvance == -2) {
        break;
      }

      if (isFirstMacroblock == 0 && macroblockAdvance > 1) {
        context->decodeSkipRun(context, static_cast<unsigned int>(macroblockAdvance));
        MPVDEC_ResetMv(reinterpret_cast<MPVMotionState*>(&context->forwardPredictionVector));
        MPVDEC_ResetDc(reinterpret_cast<MPVDecoderContextPrefix*>(context));
      } else if (context->macroblockLinearIndex > context->lastDecodedMacroblockIndex + 1) {
        context->macroblockDiscontinuityHandler(context);
      }

      if ((context->macroblockTypeFlags & 0x20) == 0) {
        const std::uint32_t mbTypeIndex = PeekWindowBits(context->bitstreamState, 27);
        const std::int16_t mbTypeEntry = static_cast<std::int16_t>(mpvvlc_p_mbtype[mbTypeIndex]);
        const int mbTypeConsume = static_cast<int>(static_cast<std::uint8_t>(mbTypeEntry & 0xFF));

        context->macroblockTypeFlags = static_cast<int>(static_cast<unsigned int>(mbTypeEntry) >> 8);
        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          mbTypeConsume
        );
      }

      if ((context->macroblockTypeFlags & 0x10) != 0) {
        context->decodeBitWindow = static_cast<int>(
          ConsumeAndExtractBits(
            context->bitstreamState.bitWindowPrimary,
            context->bitstreamState.bitWindowSecondary,
            context->bitstreamState.bitCount,
            context->bitstreamState.byteCursor,
            5
          )
        );
      }

      if ((context->macroblockTypeFlags & 8) != 0) {
        const int decodeForwardX = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->forwardPredictionVector.decodeConfig,
          &context->forwardPredictionVector.predictorX,
          &context->forwardPredictionVector.horizontalDelta
        );
        const int decodeForwardY = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->forwardPredictionVector.decodeConfig,
          &context->forwardPredictionVector.predictorY,
          &context->forwardPredictionVector.verticalDelta
        );
        if ((decodeForwardX | decodeForwardY) != 0) {
          break;
        }
      } else {
        MPVDEC_ResetMv(reinterpret_cast<MPVMotionState*>(&context->forwardPredictionVector));
      }

      if ((context->macroblockTypeFlags & 2) != 0) {
        const std::uint32_t cbpIndex = PeekWindowBits(context->bitstreamState, 23);
        const int cbpEntry = static_cast<int>(static_cast<std::int16_t>(mpvvlc_cbp[cbpIndex]));
        const int cbpConsume = cbpEntry & 0xFF;
        context->predictionSignState = (cbpEntry & 0xFFFFFFF0) << 16;

        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          cbpConsume
        );
      } else {
        context->predictionSignState = 0;
      }

      if ((context->macroblockTypeFlags & 1) != 0) {
        context->decodeIntraMacroblock(context);
        context->decodePostIntraMacroblock(context);
      } else {
        if (context->predictionSignState != 0) {
          context->decodeResidualMacroblock(context);
        }
        context->decodePredictedModes[2](context);
        MPVDEC_ResetDc(reinterpret_cast<MPVDecoderContextPrefix*>(context));
      }

      if (context->recoverNeededFlag != 0) {
        break;
      }

      context->lastDecodedMacroblockIndex = context->macroblockLinearIndex;
      --context->serviceCountdown;
      if (context->serviceCountdown <= 0) {
        context->serviceCountdown = context->serviceReloadInterval;
        context->serviceCallback(context->serviceCallbackToken);
      }

      const int refillSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, true);
      if (context->activeChunk.size - refillSplitOffset <= 0x800) {
        MPVSjChunk tailChunk{};
        SJ_SplitChunk(&context->activeChunk, refillSplitOffset, &context->activeChunk, &tailChunk);
        SjReleaseHeadChunk(stream, context->activeChunk);
        SjSubmitTailChunk(stream, tailChunk);
        SjRequestChunk(stream, context->activeChunk);

        const int preservedBitAlignment = context->bitstreamState.bitCount & 7;
        LoadBitstreamFromChunk(context->activeChunk, preservedBitAlignment, context->bitstreamState);
      }

      isFirstMacroblock = 0;
    }

    MPVSjChunk tailChunk{};
    const int finalSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, false);
    SJ_SplitChunk(&context->activeChunk, finalSplitOffset, &context->activeChunk, &tailChunk);
    SjReleaseHeadChunk(stream, context->activeChunk);
    SjSubmitTailChunk(stream, tailChunk);
    return MPV_GoNextDelimSj(stream);
  }

  /**
   * Address: 0x00C0D880 (FUN_00C0D880)
   *
   * What it does:
   * Clears the four motion predictor slots inside the motion-state lane.
   */
  MPVMotionState* MPVDEC_ResetMv(MPVMotionState* motionState)
  {
    motionState->predictors[0] = 0;
    motionState->predictors[1] = 0;
    motionState->predictors[2] = 0;
    motionState->predictors[3] = 0;
    return motionState;
  }

  /**
   * Address: 0x00C0D8A0 (FUN_00C0D8A0)
   *
   * What it does:
   * Resets Y/Cb/Cr DC predictors to MPEG baseline value (0x400).
   */
  MPVDecoderContextPrefix* MPVDEC_ResetDc(MPVDecoderContextPrefix* context)
  {
    context->dcPredictorY = 1024;
    context->dcPredictorCr = 1024;
    context->dcPredictorCb = 1024;
    return context;
  }

  /**
   * Address: 0x00C0D8C0 (FUN_00C0D8C0)
   *
   * What it does:
   * Decodes one motion-delta VLC symbol and updates predictor/output motion
   * values, including residual-bit extension and signed wrap adjustment.
   */
  int mpvdec_MotionSub(
    MPVBitstreamState* bitstreamState,
    const MPVPredictionVectorSet::MPVMotionDecodeConfig* decodeConfig,
    int* outputVector,
    int* predictor
  )
  {
    std::uint32_t bitWindowPrimary = bitstreamState->bitWindowPrimary;
    std::uint32_t bitWindowSecondary = bitstreamState->bitWindowSecondary;
    int bitCount = bitstreamState->bitCount;
    std::uint8_t* byteCursor = bitstreamState->byteCursor;
    int decodeStatus = 0;

    std::uint32_t symbolIndex = bitWindowPrimary >> 21;
    if (bitCount > 21) {
      symbolIndex |= bitWindowSecondary >> (53 - bitCount);
    }

    const std::uint16_t* motionTable = nullptr;
    if ((symbolIndex & 0xFFFFFF80u) == 0) {
      motionTable = mpvvlc_motion_0;
    } else {
      motionTable = mpvvlc_motion_1;
      symbolIndex >>= 6;
    }

    const std::int16_t symbolEntry = static_cast<std::int16_t>(motionTable[symbolIndex]);
    int motionDelta = static_cast<std::int8_t>(symbolEntry & 0xFF);
    if (motionDelta == 127) {
      decodeStatus = -1;
    } else {
      ConsumeBits(bitWindowPrimary, bitWindowSecondary, bitCount, byteCursor, static_cast<int>((symbolEntry >> 8) & 0xFF));

      if (motionDelta != 0) {
        const int residualBitCount = decodeConfig->fCodeMinus1;
        if (residualBitCount != 0) {
          const std::uint32_t residualBits =
            ConsumeAndExtractBits(bitWindowPrimary, bitWindowSecondary, bitCount, byteCursor, residualBitCount);

          const int wrapDistance = decodeConfig->fScale - static_cast<int>(residualBits) - 1;
          const int scaledDelta = motionDelta << residualBitCount;
          if (scaledDelta <= 0) {
            motionDelta = wrapDistance + scaledDelta;
          } else {
            motionDelta = scaledDelta - wrapDistance;
          }
        }

        const int predictedMotion = (motionDelta + *predictor) << decodeConfig->wrapShift >> decodeConfig->wrapShift;
        *outputVector = predictedMotion;
        *predictor = predictedMotion;
      } else {
        *outputVector = *predictor;
      }

      if (decodeConfig->fullPelFlag != 0) {
        *outputVector *= 2;
      }
    }

    bitstreamState->bitCount = bitCount;
    bitstreamState->bitWindowSecondary = bitWindowSecondary;
    bitstreamState->bitWindowPrimary = bitWindowPrimary;
    bitstreamState->byteCursor = byteCursor;
    return decodeStatus;
  }

  /**
   * Address: 0x00C0DA80 (FUN_00C0DA80)
   *
   * What it does:
   * Decodes B-picture macroblocks from the active stream chunk, including
   * motion vectors, CBP flags, macroblock mode dispatch, and chunk refills.
   */
  int MPVDEC_DecBpicMb(MPVDecoderScanContext* context, MPVSjStream* stream)
  {
    int isFirstMacroblock = 1;
    SjRequestChunk(stream, context->activeChunk);
    LoadBitstreamFromChunk(context->activeChunk, context->sliceBitAlignment, context->bitstreamState);

    while (true) {
      if (PeekWindowBits(context->bitstreamState, 9) == 0) {
        break;
      }

      const int previousLinearIndex = context->macroblockLinearIndex;
      int mbaiCode = 0;
      std::int16_t mbaiEntry = 0;
      while (true) {
        std::uint32_t mbaiIndex = PeekWindowBits(context->bitstreamState, 21);
        const std::uint16_t* mbaiTable = mpvvlc_mbai_b_0;
        if ((mbaiIndex & 0xFFFFFF80u) != 0) {
          mbaiTable = mpvvlc_mbai_b_1;
          mbaiIndex >>= 6;
        }

        mbaiEntry = static_cast<std::int16_t>(mbaiTable[mbaiIndex]);
        const int mbaiConsume = static_cast<int>(mbaiEntry) & 0x0F;
        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          mbaiConsume
        );

        mbaiCode = static_cast<int>(static_cast<std::uint8_t>(mbaiEntry >> 2)) >> 2;
        if (mbaiCode == 34) {
          continue;
        }

        if (mbaiCode == 35) {
          context->macroblockLinearIndex += 33;
          continue;
        }

        break;
      }

      if (mbaiCode == 36) {
        break;
      }

      context->macroblockLinearIndex += mbaiCode;
      context->macroblockTypeFlags = static_cast<int>(static_cast<unsigned int>(mbaiEntry) >> 10);
      if (context->macroblockLinearIndex > context->macroblockLinearLimit) {
        break;
      }

      const unsigned int macroblockAdvance = static_cast<unsigned int>(context->macroblockLinearIndex - previousLinearIndex);
      context->macroblockColumn += static_cast<int>(macroblockAdvance);
      while (context->macroblockColumn >= context->macroblocksPerRow) {
        context->macroblockColumn -= context->macroblocksPerRow;
        ++context->macroblockRow;
      }

      if (macroblockAdvance == 0xFFFFFFFEu) {
        break;
      }

      if (isFirstMacroblock == 0 && macroblockAdvance > 1) {
        context->decodeSkipRun(context, macroblockAdvance);
        MPVDEC_ResetDc(reinterpret_cast<MPVDecoderContextPrefix*>(context));
      }

      if (context->macroblockLinearIndex > context->lastDecodedMacroblockIndex + 1) {
        context->macroblockDiscontinuityHandler(context);
      }

      if ((context->macroblockTypeFlags & 0x20) == 0) {
        const std::uint32_t mbTypeIndex = PeekWindowBits(context->bitstreamState, 26);
        const std::int16_t mbTypeEntry = static_cast<std::int16_t>(mpvvlc_b_mbtype[mbTypeIndex]);
        const int mbTypeConsume = static_cast<int>(static_cast<std::uint8_t>(mbTypeEntry & 0xFF));

        context->macroblockTypeFlags = static_cast<int>(static_cast<unsigned int>(mbTypeEntry) >> 8);
        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          mbTypeConsume
        );
      }

      if ((context->macroblockTypeFlags & 0x10) != 0) {
        context->decodeBitWindow = static_cast<int>(
          ConsumeAndExtractBits(
            context->bitstreamState.bitWindowPrimary,
            context->bitstreamState.bitWindowSecondary,
            context->bitstreamState.bitCount,
            context->bitstreamState.byteCursor,
            5
          )
        );
      }

      if ((context->macroblockTypeFlags & 8) != 0) {
        const int decodeForwardX = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->forwardPredictionVector.decodeConfig,
          &context->forwardPredictionVector.predictorX,
          &context->forwardPredictionVector.horizontalDelta
        );
        const int decodeForwardY = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->forwardPredictionVector.decodeConfig,
          &context->forwardPredictionVector.predictorY,
          &context->forwardPredictionVector.verticalDelta
        );
        if ((decodeForwardX | decodeForwardY) != 0) {
          break;
        }
      }

      if ((context->macroblockTypeFlags & 4) != 0) {
        const int decodeBackwardX = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->backwardPredictionVector.decodeConfig,
          &context->backwardPredictionVector.predictorX,
          &context->backwardPredictionVector.horizontalDelta
        );
        const int decodeBackwardY = mpvdec_MotionSub(
          &context->bitstreamState,
          &context->backwardPredictionVector.decodeConfig,
          &context->backwardPredictionVector.predictorY,
          &context->backwardPredictionVector.verticalDelta
        );
        if ((decodeBackwardX | decodeBackwardY) != 0) {
          break;
        }
      }

      if ((context->macroblockTypeFlags & 2) != 0) {
        const std::uint32_t cbpIndex = PeekWindowBits(context->bitstreamState, 23);
        const int cbpEntry = static_cast<int>(static_cast<std::int16_t>(mpvvlc_cbp[cbpIndex]));
        const int cbpConsume = cbpEntry & 0xFF;
        context->predictionSignState = (cbpEntry & 0xFFFFFFF0) << 16;

        ConsumeBits(
          context->bitstreamState.bitWindowPrimary,
          context->bitstreamState.bitWindowSecondary,
          context->bitstreamState.bitCount,
          context->bitstreamState.byteCursor,
          cbpConsume
        );
      } else {
        context->predictionSignState = 0;
      }

      if ((context->macroblockTypeFlags & 1) != 0) {
        context->decodeIntraMacroblock(context);
        context->decodePostIntraMacroblock(context);
        MPVDEC_ResetMv(reinterpret_cast<MPVMotionState*>(&context->forwardPredictionVector));
        MPVDEC_ResetMv(reinterpret_cast<MPVMotionState*>(&context->backwardPredictionVector));
      } else {
        const int modeIndex = (context->macroblockTypeFlags >> 2) & 3;
        const MPVDecodeContextFn decodeMode = context->decodePredictedModes[modeIndex];
        context->decodePredictedModes[0] = decodeMode;
        if (context->predictionSignState != 0) {
          context->decodeResidualMacroblock(context);
        }
        decodeMode(context);
        MPVDEC_ResetDc(reinterpret_cast<MPVDecoderContextPrefix*>(context));
      }

      if (context->recoverNeededFlag != 0) {
        break;
      }

      context->lastDecodedMacroblockIndex = context->macroblockLinearIndex;
      --context->serviceCountdown;
      if (context->serviceCountdown <= 0) {
        context->serviceCountdown = context->serviceReloadInterval;
        context->serviceCallback(context->serviceCallbackToken);
      }

      const int refillSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, true);
      if (context->activeChunk.size - refillSplitOffset <= 0x800) {
        MPVSjChunk tailChunk{};
        SJ_SplitChunk(&context->activeChunk, refillSplitOffset, &context->activeChunk, &tailChunk);
        SjReleaseHeadChunk(stream, context->activeChunk);
        SjSubmitTailChunk(stream, tailChunk);
        SjRequestChunk(stream, context->activeChunk);

        const int preservedBitAlignment = context->bitstreamState.bitCount & 7;
        LoadBitstreamFromChunk(context->activeChunk, preservedBitAlignment, context->bitstreamState);
      }

      isFirstMacroblock = 0;
    }

    MPVSjChunk tailChunk{};
    const int finalSplitOffset = ComputeBitstreamSplitOffset(context->bitstreamState, context->activeChunk.data, false);
    SJ_SplitChunk(&context->activeChunk, finalSplitOffset, &context->activeChunk, &tailChunk);
    SjReleaseHeadChunk(stream, context->activeChunk);
    SjSubmitTailChunk(stream, tailChunk);
    return MPV_GoNextDelimSj(stream);
  }

  /**
   * Address: 0x00C0E1B0 (FUN_00C0E1B0)
   *
   * What it does:
   * Clears six scan scratch buffers and probes intra scan flags through the
   * intra read-kernel callback chain.
   */
  int MPVDEC_InitScanStateIntra(MPVDecoderScanContext* context)
  {
    ClearScanScratchBlocks<6>(context);

    context->decodeBitstreamWord = context->decodeBitWindow;
    context->decodeCurrentSource = PointerToAddress(context->decodeWorkScratchIntra);
    context->decodePhase = 0;
    context->decodeHuffmanSecondary = context->decodeTablePrimary;
    context->decodeHuffmanPrimary = PointerToAddress(&context->dcPredictorY);

    context->decodeFlags[0] = ProbeScanSlot<0>(context, context->decodeReadKernelIntra);
    context->decodeFlags[1] = ProbeScanSlot<1>(context, context->decodeReadKernelIntra);
    context->decodeFlags[2] = ProbeScanSlot<2>(context, context->decodeReadKernelIntra);
    context->decodeFlags[3] = ProbeScanSlot<3>(context, context->decodeReadKernelIntra);

    context->decodeHuffmanSecondary = context->decodeTableSecondary;
    context->decodeHuffmanPrimary = PointerToAddress(&context->dcPredictorCb);
    context->decodeFlags[4] = ProbeScanSlot<4>(context, context->decodeReadKernelIntra);

    context->decodeHuffmanPrimary = PointerToAddress(&context->dcPredictorCr);
    context->decodeFlags[5] = ProbeScanSlot<5>(context, context->decodeReadKernelIntra);

    context->decodeFinalizeIntra(context->decodeFlags);
    return 0;
  }

  /**
   * Address: 0x00C0E2E0 (FUN_00C0E2E0)
   *
   * What it does:
   * Initializes predicted scan decode state and conditionally probes six scan
   * buffers using the sign-ladder gate.
   */
  int MPVDEC_InitScanStatePredicted(MPVDecoderScanContext* context)
  {
    context->decodeBitstreamWord = context->decodeBitWindow;
    context->decodeCurrentSource = PointerToAddress(context->decodeWorkScratchPredicted);
    context->decodePhase = 1;

    int signLadder = context->predictionSignState * 4;
    context->decodeSignLadder = signLadder;

    const MPVDecodeReadKernelFn readKernel = context->decodeReadKernelPredicted;
    const std::uint8_t* scanScratchBase = context->scanScratch0;
    for (int flagIndex = 0; flagIndex < 6; ++flagIndex) {
      if (signLadder < 0) {
        context->decodeFlags[flagIndex] = ProbeScanSlot(context, readKernel, scanScratchBase);
      }

      signLadder *= 2;
      scanScratchBase += sizeof(context->scanScratch0);
    }

    context->decodeFinalizePredicted(context->decodeFlags);
    return 0;
  }
} // namespace moho::movie
