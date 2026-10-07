#pragma once

#include <cstddef>
#include <cstdint>

#include "cri/sofdec/SofdecAddressWord.h"
#include "moho/audio/SofdecRuntime.h"

namespace moho::movie
{
#ifndef MOHO_MOVIE_X86_LAYOUT_ASSERT
#define MOHO_MOVIE_X86_LAYOUT_ASSERT(expr, message) static_assert((sizeof(void*) != 4) || (expr), message)
#endif

  struct MPVDecoderScanContext;
  struct MPVPredictionKernelState;


  using MPVDecodeMacroblockFn = void(__cdecl*)(MPVDecoderScanContext*);
  using MPVInterpolationKernelFn = int(__cdecl*)(MPVPredictionKernelState*);

  struct MPVBitstreamState
  {
    std::uint32_t bitWindowPrimary;   // +0x00
    std::uint32_t bitWindowSecondary; // +0x04
    int bitCount;                     // +0x08
    std::uint8_t* byteCursor;         // +0x0C
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVBitstreamState) == 0x10, "MPVBitstreamState size must be 0x10");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVBitstreamState, bitCount) == 0x08, "MPVBitstreamState::bitCount offset must be 0x08");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVBitstreamState, byteCursor) == 0x0C, "MPVBitstreamState::byteCursor offset must be 0x0C");

  struct MPVBlockWriteTarget
  {
    std::uint8_t* pixels; // +0x00
    int stride;           // +0x04
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVBlockWriteTarget) == 0x08, "MPVBlockWriteTarget size must be 0x08");

  struct MPVCopyDestinationSet
  {
    int outputMode;                // +0x00 4 while condition 5 is set, otherwise -1 (`MPVCMC_SetCcnt`)
    MPVBlockWriteTarget blocks[6]; // +0x04
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVCopyDestinationSet) == 0x34, "MPVCopyDestinationSet size must be 0x34");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCopyDestinationSet, blocks) == 0x04, "MPVCopyDestinationSet::blocks offset must be 0x04");

  struct MPVBlockSourceSet
  {
    SofdecAddressWord clipTableAddress; // +0x00 `mpv_clip_0_255` base
    std::int16_t* sampleAddressLut;  // +0x04
    std::uint8_t* forwardSamples;    // +0x08
    std::uint8_t* backwardSamples;   // +0x0C
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVBlockSourceSet) == 0x10, "MPVBlockSourceSet size must be 0x10");

  /// One reference frame's planes as `sfmpv_SetFrmPara` lays them out: the
  /// luma plane is the frame base, U follows it and V follows U.
  struct MPVMacroblockOffsets
  {
    SofdecAddressWord chromaUPlaneAddress; // +0x00
    SofdecAddressWord chromaVPlaneAddress; // +0x04
    SofdecAddressWord lumaPlaneAddress;    // +0x08
    std::int16_t chromaStride;            // +0x0C
    std::int16_t lumaStride;              // +0x0E
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVMacroblockOffsets) == 0x10, "MPVMacroblockOffsets size must be 0x10");

  /// The per-frame decode request `sfmpv_DecodeFrm` hands `MPV_DecodeFrmSj`.
  /// The decoder copies it whole into the handle (`frameSession` at +0x264) and
  /// writes the two recover deltas back when the picture is done.
  struct MPVFrameDecodeSession
  {
    MPVMacroblockOffsets forwardReference;  // +0x00
    MPVMacroblockOffsets backwardReference; // +0x10
    SofdecAddressWord outputFrameAddress;   // +0x20 `MPVUMC_InitOutRfb` lays the output planes out from here
    SofdecAddressWord pictureAttributesAddress; // +0x24
    int recoverEventDelta;                  // +0x28
    int recoverConditionDelta;              // +0x2C
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVFrameDecodeSession) == 0x30, "MPVFrameDecodeSession size must be 0x30");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVFrameDecodeSession, outputFrameAddress) == 0x20, "MPVFrameDecodeSession::outputFrameAddress offset must be 0x20");

  /// Per-handle error lane (`MPVERR_InitErrInf` clears all 0x14 bytes and
  /// `MPV_GetErrInf` copies them out, recover counters included).
  struct MPVErrorInfo
  {
    SofdecAddressWord callbackAddress; // +0x00
    int callbackContext;               // +0x04
    int errorCode;                     // +0x08
    int recoverEventCounter;           // +0x0C
    int recoverConditionCounter;       // +0x10
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVErrorInfo) == 0x14, "MPVErrorInfo size must be 0x14");

  struct MPVSpatialDelta
  {
    int luma;   // +0x00
    int chroma; // +0x04
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVSpatialDelta) == 0x08, "MPVSpatialDelta size must be 0x08");

  struct MPVPredictionKernelState
  {
    std::int32_t reserved_00[6]; // +0x00
    int destinationBlockBase;    // +0x18
    std::int32_t reserved_1C;    // +0x1C
    int destinationStride;       // +0x20
    int sourcePrimary;           // +0x24
    int sourceSecondary;         // +0x28
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionKernelState, destinationBlockBase) == 0x18, "MPVPredictionKernelState::destinationBlockBase offset must be 0x18");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionKernelState, destinationStride) == 0x20, "MPVPredictionKernelState::destinationStride offset must be 0x20");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionKernelState, sourcePrimary) == 0x24, "MPVPredictionKernelState::sourcePrimary offset must be 0x24");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionKernelState, sourceSecondary) == 0x28, "MPVPredictionKernelState::sourceSecondary offset must be 0x28");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVPredictionKernelState) == 0x2C, "MPVPredictionKernelState size must be 0x2C");

  struct MPVPredictionVectorSet
  {
    struct MPVMotionDecodeConfig
    {
      int fullPelFlag;  // +0x00
      int fCodeMinus1;  // +0x04
      int wrapShift;    // +0x08
      int fScale;       // +0x0C
    };

    MPVMotionDecodeConfig decodeConfig; // +0x00
    int predictorX;             // +0x10
    int predictorY;             // +0x14
    int horizontalDelta;        // +0x18
    int verticalDelta;          // +0x1C
    std::int32_t reserved_20;   // +0x20
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionVectorSet, decodeConfig) == 0x00, "MPVPredictionVectorSet::decodeConfig offset must be 0x00");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionVectorSet, predictorX) == 0x10, "MPVPredictionVectorSet::predictorX offset must be 0x10");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionVectorSet, predictorY) == 0x14, "MPVPredictionVectorSet::predictorY offset must be 0x14");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionVectorSet, horizontalDelta) == 0x18, "MPVPredictionVectorSet::horizontalDelta offset must be 0x18");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPredictionVectorSet, verticalDelta) == 0x1C, "MPVPredictionVectorSet::verticalDelta offset must be 0x1C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVPredictionVectorSet) == 0x24, "MPVPredictionVectorSet size must be 0x24");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVPredictionVectorSet::MPVMotionDecodeConfig) == 0x10, "MPVMotionDecodeConfig size must be 0x10");

  struct MPVMotionState
  {
    std::int32_t reserved[4];   // +0x00
    std::int32_t predictors[4]; // +0x10
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVMotionState, predictors) == 0x10, "MPVMotionState::predictors offset must be 0x10");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVMotionState) == 0x20, "MPVMotionState size must be 0x20");

  using MPVDecodeReadKernelFn = std::uint8_t(__cdecl*)(MPVDecoderScanContext* decoderContext, void* decodeState);
  using MPVDecodeContextFn = void(__cdecl*)(MPVDecoderScanContext* decoderContext);
  using MPVDecodeSkipRunFn = void(__cdecl*)(MPVDecoderScanContext* decoderContext, unsigned int skipCount);
  using MPVDecodeSliceFn = int(__cdecl*)(MPVDecoderScanContext* context, moho::SofdecSjSupplyHandle* stream);
  using MPVSkipMacroblockFn = int(__cdecl*)(MPVDecoderScanContext* context, int skippedMacroblockCount);
  using MPVMacroblockDecodeFn = int(__cdecl*)(MPVDecoderScanContext* context);
  using MPVDctTransformFn = int(__cdecl*)(MPVDecoderScanContext* handle);
  using MPVConcealFrameFn = int(__cdecl*)(SofdecAddressWord handleAddress);
  using MPVDecoderServiceFn = void(__cdecl*)(SofdecAddressWord serviceToken);

  struct MPVUserSjLane
  {
    SofdecAddressWord streamObjectAddress;   // +0x00
    SofdecAddressWord streamCallbackAddress; // +0x04 (x86)
    SofdecAddressWord streamContextAddress;  // +0x08 (x86)
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVUserSjLane) == 0x0C, "MPVUserSjLane size must be 0x0C");

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

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVPictureAttributes) == 0x6C, "MPVPictureAttributes size must be 0x6C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPictureAttributes, pictureCodingType) == 0x38, "MPVPictureAttributes::pictureCodingType offset must be 0x38");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPictureAttributes, forwardFCode) == 0x50, "MPVPictureAttributes::forwardFCode offset must be 0x50");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPictureAttributes, qScaleType) == 0x59, "MPVPictureAttributes::qScaleType offset must be 0x59");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVPictureAttributes, extensionFlags) == 0x68, "MPVPictureAttributes::extensionFlags offset must be 0x68");

  struct MPVPictureAttributeExportBlock
  {
    MPVPictureAttributes pictureAttributes;
    std::uint8_t reserved_6C_to_7F[0x14];
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVPictureAttributeExportBlock) == 0x80, "MPVPictureAttributeExportBlock size must be 0x80");

  /**
   * The per-block working state the read kernels
   * (`mpvhdec_ReadKernel*`, 0x00AFAE50 / 0x00AFD7C0) carry alongside the scan
   * context. Every lane below is taken from their own accesses; the run/level
   * quartet at the front is what each VLC path fills in before the coefficient
   * is emitted.
   *
   * Dequantization is
   * `(quantScale * 2 * level * quantMatrix[scanIndex]) >> 4`, negated by sign,
   * then multiplied by `MPVDecoderScanContext::dequantScaleTable[scanIndex]`
   * on its way into `coefficients`.
   *
   * NOTE the field order: `run` is at +0x00 and `level` at +0x04, which is
   * the opposite of the order the names suggest. Both kernels take the run
   * from the low byte of a VLC table entry and the level from the (signed)
   * next byte up, so a swapped model decodes every coefficient wrongly while
   * still building, linking and running.
   */
  /**
   * This block lives inside the scan context, at +0x44, as
   * `MPVDecoderScanContext::coefficientDecodeState`. The scan-state
   * initializers fill its per-macroblock lanes and then pass its address as
   * the kernel's second argument; the kernel reads and writes the same
   * storage. Never allocate a detached one and write through it - the decoder
   * would keep reading the context and silently produce wrong coefficients.
   */
  struct MPVCoefficientDecodeState
  {
    /**
     * Zero coefficients to skip before the one this code carries; the scan
     * cursor advances by `run + 1`. The escape marker in the short-code
     * table is a run of 64, which no real code can produce.
     */
    std::int32_t run;            // +0x00
    /** Signed magnitude fed to the dequantizer; a level of zero ends the block. */
    std::int32_t level;          // +0x04
    std::int32_t signBit;        // +0x08
    std::int32_t codeLengthBits; // +0x0C
    std::int32_t scanIndexLimit; // +0x10
    std::int32_t scanIndex;      // +0x14
    std::uint8_t reserved_18[0x04];
    float* coefficients;              // +0x1C
    const std::uint8_t* quantMatrix;  // +0x20
    std::int32_t quantScale;          // +0x24
    std::int32_t* dcAccumulator;      // +0x28
    const std::uint8_t* dcSizeTable;  // +0x2C
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, codeLengthBits) == 0x0C, "MPVCoefficientDecodeState::codeLengthBits offset must be 0x0C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, scanIndex) == 0x14, "MPVCoefficientDecodeState::scanIndex offset must be 0x14");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, coefficients) == 0x1C, "MPVCoefficientDecodeState::coefficients offset must be 0x1C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, quantMatrix) == 0x20, "MPVCoefficientDecodeState::quantMatrix offset must be 0x20");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, quantScale) == 0x24, "MPVCoefficientDecodeState::quantScale offset must be 0x24");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, dcAccumulator) == 0x28, "MPVCoefficientDecodeState::dcAccumulator offset must be 0x28");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVCoefficientDecodeState, dcSizeTable) == 0x2C, "MPVCoefficientDecodeState::dcSizeTable offset must be 0x2C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVCoefficientDecodeState) == 0x30, "MPVCoefficientDecodeState size must be 0x30");

  struct MPVAbdecRunLevelLane
  {
    SofdecAddressWord tableBaseMinusBias; // +0x00
    std::int32_t bitLength;               // +0x04 (x86)
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVAbdecRunLevelLane) == 0x08, "MPVAbdecRunLevelLane size must be 0x08");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVAbdecRunLevelLane, tableBaseMinusBias) == 0x00, "MPVAbdecRunLevelLane::tableBaseMinusBias offset must be 0x00");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVAbdecRunLevelLane, bitLength) == 0x04, "MPVAbdecRunLevelLane::bitLength offset must be 0x04");

  /// The table block `mpvlib_InitWork` places past the decoder slots (0x3A0 into
  /// the object table). Every decoder handle points into it: the AB-decode mask,
  /// scan and threshold tables, the dequantisation scale table, the run-level
  /// lane descriptors, the VLC tables (`mpvvlc_SetupVlc` fills the arena from its
  /// end downward) and the 0..255 clip table.
  struct MPVSharedWork
  {
    std::uint8_t reserved_0000[0x1100];          // +0x0000
    std::uint32_t forwardMaskLut[8];             // +0x1100 also read as the 16-bit mask-by-width table
    std::uint8_t intraScanPermutation[64];       // +0x1120
    float dequantScaleTable[64];                 // +0x1160 (`DCT_FsriInitScaleTbl`)
    std::uint32_t thresholdLut[8];               // +0x1260
    MPVAbdecRunLevelLane runLevelLanes[6];       // +0x1280
    std::uint8_t vlcTableArena[0x5B0];           // +0x12B0
    std::int32_t clipTableStorage[0x100];        // +0x1860 (`mpvlib_InitClip`)
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVSharedWork, forwardMaskLut) == 0x1100, "MPVSharedWork::forwardMaskLut offset must be 0x1100");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVSharedWork, runLevelLanes) == 0x1280, "MPVSharedWork::runLevelLanes offset must be 0x1280");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVSharedWork, vlcTableArena) == 0x12B0, "MPVSharedWork::vlcTableArena offset must be 0x12B0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVSharedWork, clipTableStorage) == 0x1860, "MPVSharedWork::clipTableStorage offset must be 0x1860");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVSharedWork) == 0x1C60, "MPVSharedWork size must be 0x1C60");

  struct MPVDecoderScanContext
  {
    static constexpr int kServiceReloadIntervalCondition = 7;
    static constexpr int kServiceCallbackCondition = 8;
    static constexpr int kServiceCallbackTokenCondition = 9;

    MPVBitstreamState bitstreamState; // +0x00
    const std::uint32_t* acShortRunLevelTable; // +0x10
    const std::uint16_t* acLongRunLevelTables[6]; // +0x14 .. +0x2B (x86)
    std::uint8_t* coefficientWriteCursor; // +0x2C
    const std::uint16_t* bitMaskByWidth; // +0x30
    const float* dequantScaleTable; // +0x34
    SofdecAddressWord abdecThresholdLutAddress; // +0x38
    SofdecAddressWord abdecRunLevelLanesAddress; // +0x3C
    SofdecAddressWord lumaBaseAddress; // +0x40
    MPVCoefficientDecodeState coefficientDecodeState; // +0x44
    int blockScanPhase; // +0x74
    std::uint8_t decodeFlags[6]; // +0x78
    std::uint8_t reserved_007E[0x90 - 0x7E];
    int primaryDctDecodeCount; // +0x90
    int secondaryDctDecodeCount; // +0x94
    std::uint8_t reserved_0098[0xA0 - 0x98];
    int codedBlockPatternMask; // +0xA0 one bit per block, MSB first
    float* dctCoefficients; // +0xA4 six 64-coefficient blocks (`scanScratch0` onward)
    SofdecAddressWord* dctBlockOutputAddresses; // +0xA8 the six block output addresses (`scanScratchAddress4A0` onward)
    std::uint8_t reserved_00AC[0xC0 - 0xAC];
    SofdecAddressWord dctScaleTableAddress; // +0xC0
    std::uint8_t reserved_00C4[0xCC - 0xC4];
    MPVPredictionKernelState predictionKernelState; // +0xCC
    std::uint8_t reserved_00F8[0x110 - 0xF8];
    MPVBlockSourceSet blockSources; // +0x110 clip table, scan LUT and the two prediction scratch areas
    MPVCopyDestinationSet copyTargets; // +0x120 reconstruction output blocks (`MPVCMC_InitMcOiRt`)
    MPVCopyDestinationSet scratchTargets; // +0x154 prediction scratch blocks (`mpvcmc_InitMcOiTa`)
    int objectSlotState; // +0x188
    int objectInitStatus; // +0x18C
    SofdecAddressWord conditionCallbacks[16]; // +0x190
    MPVPictureAttributes pictureAttributes; // +0x1D0
    std::uint8_t reserved_023C[0x250 - 0x23C];
    MPVErrorInfo errorInfo; // +0x250
    MPVFrameDecodeSession frameSession; // +0x264
    SofdecAddressWord planeBase0; // +0x294
    SofdecAddressWord planeBase1; // +0x298
    SofdecAddressWord planeBase2; // +0x29C
    std::int16_t planeBase1Stride; // +0x2A0
    std::int16_t planeBase2Stride; // +0x2A2
    int sequenceAspectRatioCode; // +0x2A4
    int sequenceBitRateCode; // +0x2A8
    int sequenceVbvBufferCode; // +0x2AC
    int constrainedParametersFlag; // +0x2B0
    int gopClosedFlag; // +0x2B4
    int gopBrokenLinkFlag; // +0x2B8
    int pictureVbvDelay; // +0x2BC
    MPVDecodeSliceFn decodeMacroblockByType; // +0x2C0
    MPVDecodeSkipRunFn decodeSkipRun; // +0x2C4
    MPVDecodeContextFn decodeIntraMacroblock; // +0x2C8
    MPVDecodeContextFn decodeResidualMacroblock; // +0x2CC
    MPVDecodeContextFn decodePostIntraMacroblock; // +0x2D0
    MPVDecodeContextFn decodePredictedModes[4]; // +0x2D4 .. +0x2E3
    MPVDctTransformFn dctTransformSixBlocks; // +0x2E4 intra pictures: all six blocks
    MPVDctTransformFn dctTransformCbp; // +0x2E8 predicted pictures: the coded-block-pattern blocks
    int decodeBitWindow; // +0x2EC
    MPVPredictionVectorSet forwardPredictionVector; // +0x2F0
    MPVPredictionVectorSet backwardPredictionVector; // +0x314
    int macroblockLinearIndex; // +0x338
    int macroblockRow; // +0x33C
    int macroblockColumn; // +0x340
    int macroblockLinearLimit; // +0x344
    int macroblockTypeFlags; // +0x348
    int predictionSignState; // +0x34C
    std::int32_t dcPredictorY; // +0x350
    std::int32_t dcPredictorCb; // +0x354
    std::int32_t dcPredictorCr; // +0x358
    int pictureCodecClassification; // +0x35C
    int sequenceStcCodePrimary; // +0x360
    int sequenceStcCodeSecondary; // +0x364
    int sequenceStcCodeTertiary; // +0x368
    SofdecAddressWord scanScratchAddress4A0; // +0x36C
    SofdecAddressWord scanScratchAddress520; // +0x370
    SofdecAddressWord scanScratchAddress5A0; // +0x374
    SofdecAddressWord scanScratchAddress620; // +0x378
    SofdecAddressWord scanScratchAddress3A0; // +0x37C
    SofdecAddressWord scanScratchAddress420; // +0x380
    std::uint8_t reserved_0384[0x3A0 - 0x384];
    std::int16_t intraCopyAddressLut[384]; // +0x3A0 .. +0x69F
    std::uint8_t scanScratch0[0x100]; // +0x6A0
    std::uint8_t scanScratch1[0x100]; // +0x7A0
    std::uint8_t scanScratch2[0x100]; // +0x8A0
    std::uint8_t scanScratch3[0x100]; // +0x9A0
    std::uint8_t scanScratch4[0x100]; // +0xAA0
    std::uint8_t scanScratch5[0x100]; // +0xBA0
    std::uint8_t decodeWorkScratchIntra[0x40]; // +0xCA0
    std::uint8_t decodeWorkScratchPredicted[0x258]; // +0xCE0
    std::uint8_t reserved_0F38[0x1320 - 0x0F38];
    int recoverNeededFlag; // +0x1320
    int recoverState; // +0x1324
    moho::SjChunkRange activeChunk; // +0x1328
    int sliceBitAlignment; // +0x1330
    int sequenceUserDataIdcPrecisionMode; // +0x1334
    MPVDecodeReadKernelFn decodeReadKernelIntra; // +0x1338
    MPVDecodeReadKernelFn decodeReadKernelPredicted; // +0x133C
    std::uint8_t reserved_1340[0x1344 - 0x1340];
    int serviceCountdown; // +0x1344
    const std::uint8_t* decodeTablePrimary; // +0x1348
    const std::uint8_t* decodeTableSecondary; // +0x134C
    SofdecAddressWord m2vDecoderHandle; // +0x1350
    SofdecAddressWord currentHeaderContext; // +0x1354
    MPVUserSjLane userSjLanes[4]; // +0x1358
    SofdecAddressWord pictureUserBufferAddress; // +0x1388
    int pictureUserBufferBytes; // +0x138C
    int pictureUserDecodeState; // +0x1390
    int reserved_1394; // +0x1394
    MPVDecodeContextFn macroblockDiscontinuityHandler; // +0x1398
    int lastDecodedMacroblockIndex; // +0x139C
    int postCreateMarker; // +0x13A0
    int headerProgressPrimary; // +0x13A4
    int headerProgressSecondary; // +0x13A8
    int motionClampCounter; // +0x13AC

    [[nodiscard]] std::int16_t* scanLut3A0() noexcept { return intraCopyAddressLut; }
    [[nodiscard]] std::int16_t* scanLut420() noexcept { return intraCopyAddressLut + 64; }
    [[nodiscard]] std::int16_t* scanLut4A0() noexcept { return intraCopyAddressLut + 128; }
    [[nodiscard]] std::int16_t* scanLut520() noexcept { return intraCopyAddressLut + 192; }
    [[nodiscard]] std::int16_t* scanLut5A0() noexcept { return intraCopyAddressLut + 256; }
    [[nodiscard]] std::int16_t* scanLut620() noexcept { return intraCopyAddressLut + 320; }
    [[nodiscard]] int macroblocksPerRow() const noexcept { return pictureAttributes.headerControlWords[2]; }
    [[nodiscard]] int& macroblocksPerRow() noexcept { return pictureAttributes.headerControlWords[2]; }
    [[nodiscard]] int macroblockRowsCount() const noexcept { return pictureAttributes.headerControlWords[3]; }
    [[nodiscard]] int& macroblockRowsCount() noexcept { return pictureAttributes.headerControlWords[3]; }
    [[nodiscard]] int coefficientScanMode() const noexcept { return pictureAttributes.headerControlWords[6]; }
    [[nodiscard]] int& coefficientScanMode() noexcept { return pictureAttributes.headerControlWords[6]; }
    [[nodiscard]] int interpolationParity() const noexcept { return static_cast<int>(conditionCallbacks[3]); }
    [[nodiscard]] SofdecAddressWord serviceReloadInterval() const noexcept { return conditionCallbacks[kServiceReloadIntervalCondition]; }
    [[nodiscard]] SofdecAddressWord& serviceReloadInterval() noexcept { return conditionCallbacks[kServiceReloadIntervalCondition]; }
    [[nodiscard]] MPVDecoderServiceFn serviceCallback() const noexcept
    {
      return reinterpret_cast<MPVDecoderServiceFn>(static_cast<std::uintptr_t>(conditionCallbacks[kServiceCallbackCondition]));
    }
    [[nodiscard]] SofdecAddressWord serviceCallbackToken() const noexcept { return conditionCallbacks[kServiceCallbackTokenCondition]; }
  };

  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, bitstreamState) == 0x00, "MPVDecoderScanContext::bitstreamState offset must be 0x00");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, acShortRunLevelTable) == 0x10, "MPVDecoderScanContext::acShortRunLevelTable offset must be 0x10");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, acLongRunLevelTables) == 0x14, "MPVDecoderScanContext::acLongRunLevelTables offset must be 0x14");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, coefficientWriteCursor) == 0x2C, "MPVDecoderScanContext::coefficientWriteCursor offset must be 0x2C");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, bitMaskByWidth) == 0x30, "MPVDecoderScanContext::bitMaskByWidth offset must be 0x30");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, dequantScaleTable) == 0x34, "MPVDecoderScanContext::dequantScaleTable offset must be 0x34");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, coefficientDecodeState) == 0x44, "MPVDecoderScanContext::coefficientDecodeState offset must be 0x44");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, primaryDctDecodeCount) == 0x90, "MPVDecoderScanContext::primaryDctDecodeCount offset must be 0x90");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, blockSources) == 0x110, "MPVDecoderScanContext::blockSources offset must be 0x110");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, copyTargets) == 0x120, "MPVDecoderScanContext::copyTargets offset must be 0x120");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, scratchTargets) == 0x154, "MPVDecoderScanContext::scratchTargets offset must be 0x154");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, objectSlotState) == 0x188, "MPVDecoderScanContext::objectSlotState offset must be 0x188");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, conditionCallbacks) == 0x190, "MPVDecoderScanContext::conditionCallbacks offset must be 0x190");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, pictureAttributes) == 0x1D0, "MPVDecoderScanContext::pictureAttributes offset must be 0x1D0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, errorInfo) == 0x250, "MPVDecoderScanContext::errorInfo offset must be 0x250");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, frameSession) == 0x264, "MPVDecoderScanContext::frameSession offset must be 0x264");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, planeBase0) == 0x294, "MPVDecoderScanContext::planeBase0 offset must be 0x294");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, sequenceAspectRatioCode) == 0x2A4, "MPVDecoderScanContext::sequenceAspectRatioCode offset must be 0x2A4");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, decodeMacroblockByType) == 0x2C0, "MPVDecoderScanContext::decodeMacroblockByType offset must be 0x2C0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, decodePredictedModes) == 0x2D4, "MPVDecoderScanContext::decodePredictedModes offset must be 0x2D4");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, forwardPredictionVector) == 0x2F0, "MPVDecoderScanContext::forwardPredictionVector offset must be 0x2F0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, macroblockLinearIndex) == 0x338, "MPVDecoderScanContext::macroblockLinearIndex offset must be 0x338");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, intraCopyAddressLut) == 0x3A0, "MPVDecoderScanContext::intraCopyAddressLut offset must be 0x3A0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, scanScratch0) == 0x6A0, "MPVDecoderScanContext::scanScratch0 offset must be 0x6A0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, decodeWorkScratchIntra) == 0xCA0, "MPVDecoderScanContext::decodeWorkScratchIntra offset must be 0xCA0");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, recoverNeededFlag) == 0x1320, "MPVDecoderScanContext::recoverNeededFlag offset must be 0x1320");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, activeChunk) == 0x1328, "MPVDecoderScanContext::activeChunk offset must be 0x1328");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, decodeReadKernelIntra) == 0x1338, "MPVDecoderScanContext::decodeReadKernelIntra offset must be 0x1338");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, decodeTablePrimary) == 0x1348, "MPVDecoderScanContext::decodeTablePrimary offset must be 0x1348");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, userSjLanes) == 0x1358, "MPVDecoderScanContext::userSjLanes offset must be 0x1358");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, pictureUserBufferAddress) == 0x1388, "MPVDecoderScanContext::pictureUserBufferAddress offset must be 0x1388");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, macroblockDiscontinuityHandler) == 0x1398, "MPVDecoderScanContext::macroblockDiscontinuityHandler offset must be 0x1398");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(offsetof(MPVDecoderScanContext, motionClampCounter) == 0x13AC, "MPVDecoderScanContext::motionClampCounter offset must be 0x13AC");
  MOHO_MOVIE_X86_LAYOUT_ASSERT(sizeof(MPVDecoderScanContext) == 0x13B0, "MPVDecoderScanContext x86 size must be 0x13B0");

  /**
   * Address: 0x00C0C000 (FUN_00C0C000)
   *
   * MPV decoder intra macroblock path.
   *
   * What it does:
   * Computes destination plane pointers for the current MB and writes the six
   * intra 8x8 blocks through the LUT-based luma copy path.
   */
  int MPVUMC_Intra(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0C080 (FUN_00C0C080)
   *
   * LUT-based block sample copy helper.
   *
   * What it does:
   * Copies six 8x8 blocks from source-address LUT entries into destination
   * targets, adding the current luma base address bias.
   */
  int MPVUMC_CopyIntraBlocks(const std::int16_t* sourceAddressLut, MPVCopyDestinationSet& destinations, int lumaBaseAddress);

  /**
   * Address: 0x00C0C390 (FUN_00C0C390)
   *
   * What it does:
   * Builds prediction pointers for one reference lane using motion deltas and
   * dispatches interpolation kernels for 6 block destinations.
   */
  int form_prediction(
    MPVDecoderScanContext* context,
    int predictionWriteBaseAddress,
    MPVSpatialDelta* outDelta,
    const MPVMacroblockOffsets* blockOffsets,
    const MPVPredictionVectorSet* motionVector
  );

  /**
   * Address: 0x00C0C1C0 (FUN_00C0C1C0)
   *
   * What it does:
   * Recovers forward-predicted MB samples then writes frame420 blocks.
   */
  int MPVUMC_Forward(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0C250 (FUN_00C0C250)
   *
   * What it does:
   * Recovers backward-predicted MB samples then writes frame420 blocks.
   */
  int MPVUMC_Backward(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0C2E0 (FUN_00C0C2E0)
   *
   * What it does:
   * Recovers forward+backward MB samples and writes bi-directional frame420
   * blend blocks.
   */
  int MPVUMC_BiDirect(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0C5C0 (FUN_00C0C5C0)
   *
   * What it does:
   * Writes six frame-420 prediction blocks from one predictor lane, using
   * either indexed fetches or direct byte copies based on sign-state.
   */
  int addBlocksFrame420_also(MPVBlockSourceSet* source, MPVCopyDestinationSet* destinations, int predictionSignBits);

  /**
   * Address: 0x00C0C760 (FUN_00C0C760)
   *
   * What it does:
   * Writes six frame-420 prediction blocks by averaging forward/backward
   * predictor lanes, with indexed or direct byte-path based on sign-state.
   */
  int addBlocksFrame420(MPVBlockSourceSet* source, MPVCopyDestinationSet* destinations, int predictionSignBits);

  /**
   * Address: 0x00C0CC20 (FUN_00C0CC20)
   *
   * What it does:
   * Rewinds MB address by skip count and decodes B-picture skipped MBs through
   * the configured callback until the prior linear MB index is reached.
   */
  int MPVUMC_BpicSkipped(MPVDecoderScanContext* context, int skippedMacroblockCount);

  /**
   * Address: 0x00C0C9B0 (FUN_00C0C9B0)
   *
   * What it does:
   * Rewinds MB address by skip count and copies forward prediction lanes into
   * backward lanes for each skipped P-picture MB.
   */
  int MPVUMC_PpicSkipped(MPVDecoderScanContext* context, int skippedMacroblockCount);

  /**
   * Address: 0x00C0CA20 (FUN_00C0CA20)
   *
   * What it does:
   * Copies one macroblock prediction span between offset descriptors (luma and
   * packed chroma lanes) using the provided MB spatial delta.
   */
  int MPVUMC_CopyPredictionSpan(
    const MPVSpatialDelta& mbDelta, const MPVMacroblockOffsets& sourceOffsets, const MPVMacroblockOffsets& destinationOffsets
  );

  /**
   * Address: 0x00C0E1B0 (FUN_00C0E1B0)
   *
   * What it does:
   * Resets six scan scratch blocks and runs intra scan decode probes.
   */
  int MPVDEC_InitScanStateIntra(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0E2E0 (FUN_00C0E2E0)
   *
   * What it does:
   * Runs predicted scan decode probes using sign-ladder gating.
   */
  int MPVDEC_InitScanStatePredicted(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0E370 (FUN_00C0E370)
   *
   * What it does:
   * Scalar 8x8 copy kernel used by interpolation dispatch tables.
   */
  int MPVKernel_Copy8x8(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0E780 (FUN_00C0E780)
   *
   * What it does:
   * Scalar 8x8 kernel: rounded average of primary/secondary source lanes.
   */
  int MPVKernel_AvgPrimarySecondary(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0E850 (FUN_00C0E850)
   *
   * What it does:
   * Scalar 8x8 kernel: rounded horizontal average on primary source lane.
   */
  int MPVKernel_AvgHorizontal(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0E910 (FUN_00C0E910)
   *
   * What it does:
   * Scalar 8x8 kernel: quarter-sample blend from 2x2 primary/secondary pairs.
   */
  int MPVKernel_AvgHorizontalAndSecondary(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0EA50 (FUN_00C0EA50)
   *
   * What it does:
   * SSE/MMX lane variant of primary/secondary rounded-average kernel.
   */
  int MPVKernel_AvgPrimarySecondarySse(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0EB00 (FUN_00C0EB00)
   *
   * What it does:
   * SSE/MMX lane variant of horizontal rounded-average kernel.
   */
  int MPVKernel_AvgHorizontalSse(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0EBA0 (FUN_00C0EBA0)
   *
   * What it does:
   * SSE/MMX lane variant of 8x8 copy kernel.
   */
  int MPVKernel_Copy8x8Sse(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0EC20 (FUN_00C0EC20)
   *
   * What it does:
   * MMX lane variant of primary/secondary rounded-average kernel.
   */
  int MPVKernel_AvgPrimarySecondaryMmx(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0EDC0 (FUN_00C0EDC0)
   *
   * What it does:
   * MMX lane variant of horizontal rounded-average kernel.
   */
  int MPVKernel_AvgHorizontalMmx(MPVPredictionKernelState* kernelState);

  /**
   * Address: 0x00C0CC70 (FUN_00C0CC70)
   *
   * What it does:
   * Computes luma/chroma byte deltas for the current MB row/column against a
   * macroblock plane-offset descriptor.
   */
  int MPVUMC_GetMacroblockPlaneOffsets(
    const MPVDecoderScanContext* context, const MPVMacroblockOffsets& blockOffsets, MPVSpatialDelta& outDelta
  );

  /**
   * Address: 0x00C0CCB0 (FUN_00C0CCB0)
   *
   * What it does:
   * Decrements MB address by a skip amount and wraps row/column indices when
   * the column crosses the left boundary.
   */
  MPVDecoderScanContext* mpvumc_SubMbadr(MPVDecoderScanContext* context, int decrement);

  /**
   * Address: 0x00C0CD10 (FUN_00C0CD10)
   *
   * What it does:
   * Increments MB address by one and wraps row/column indices when the column
   * reaches row width.
   */
  MPVDecoderScanContext* mpvumc_IncreMbadr(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0D880 (FUN_00C0D880)
   *
   * What it does:
   * Clears the four motion predictor slots inside the motion-state lane.
   */
  MPVMotionState* MPVDEC_ResetMv(MPVMotionState* motionState);

  /**
   * Address: 0x00C0D8A0 (FUN_00C0D8A0)
   *
   * What it does:
   * Resets Y/Cb/Cr DC predictors to MPEG baseline value (0x400).
   */
  MPVDecoderScanContext* MPVDEC_ResetDc(MPVDecoderScanContext* context);

  /**
   * Address: 0x00C0D8C0 (FUN_00C0D8C0)
   *
   * What it does:
   * Decodes one motion-delta symbol from the VLC bitstream and updates the
   * caller's predictor/output vectors.
   */
  int mpvdec_MotionSub(
    MPVBitstreamState* bitstreamState, const MPVPredictionVectorSet::MPVMotionDecodeConfig* decodeConfig, int* outputVector, int* predictor
  );

  /**
   * Address: 0x00C0CD50 (FUN_00C0CD50)
   *
   * What it does:
   * Decodes I-picture macroblocks from the current slice chunk stream.
   */
  int MPVDEC_DecIpicMb(MPVDecoderScanContext* context, moho::SofdecSjSupplyHandle* stream);

  /**
   * Address: 0x00C0D1D0 (FUN_00C0D1D0)
   *
   * What it does:
   * Decodes P-picture macroblocks from the current slice chunk stream.
   */
  int MPVDEC_DecPpicMb(MPVDecoderScanContext* context, moho::SofdecSjSupplyHandle* stream);

  /**
   * Address: 0x00C0DA80 (FUN_00C0DA80)
   *
   * What it does:
   * Decodes B-picture macroblocks from the current slice chunk stream,
   * including MBAI/MB-type/CBP/motion paths and chunk refill handling.
   */
  int MPVDEC_DecBpicMb(MPVDecoderScanContext* context, moho::SofdecSjSupplyHandle* stream);
} // namespace moho::movie

extern "C"
{
  /**
   * Address: 0x00AE7950 (FUN_00AE7950, _MPV_Init)
   *
   * What it does:
   * Library entry point: publishes the CRI banner, runs the fatal preflight,
   * carves `objectCount` decoder slots plus the conceal-state arena out of
   * `workAddress`, and initializes every MPV decode stage against it.
   */
  std::int32_t MPV_Init(std::int32_t objectCount, SofdecAddressWord workAddress);

  /**
   * Address: 0x00AEAE60 (FUN_00AEAE60, _MPVERR_Init)
   *
   * What it does:
   * Resets the library-wide MPV error record.
   */
  void* MPVERR_Init();

  /**
   * Address: 0x00AEAB10 (FUN_00AEAB10, _MPVFRM_Init)
   *
   * What it does:
   * Frame-store startup hook (no-op in the PC build).
   */
  void MPVFRM_Init();

  /**
   * Address: 0x00AF61F0 (FUN_00AF61F0, _MPVBDEC_Init)
   *
   * What it does:
   * Initializes block-decode state in the runtime work arena.
   */
  int MPVBDEC_Init(moho::movie::MPVSharedWork* sharedWork);

  /**
   * Address: 0x00AF6030 (FUN_00AF6030, _MPVUMC_Init)
   *
   * What it does:
   * Initializes the motion-compensation stage.
   */
  int MPVUMC_Init();

  /**
   * Address: 0x00AF5E70 (FUN_00AF5E70, _MPVCDEC_Init)
   *
   * What it does:
   * Initializes the colour-conversion stage.
   */
  int MPVCDEC_Init();

  /**
   * Address: 0x00AE79E0 (FUN_00AE79E0, _mpvlib_ChkFatal)
   *
   * What it does:
   * Validates MPV runtime prerequisites (VLC-table sizing and decoder version)
   * and maps failures to MPV error codes.
   */
  int mpvlib_ChkFatal();

  /**
   * Address: 0x00AE7A30 (FUN_00AE7A30, _mpvlib_ChkCacheMode)
   *
   * What it does:
   * Cache-mode compatibility hook (no-op in the PC build).
   */
  void mpvlib_ChkCacheMode();

  /**
   * Address: 0x00AE7A40 (FUN_00AE7A40, _MPVLIB_ConvWorkAddr)
   *
   * What it does:
   * Converts caller-provided work memory address into runtime work-space
   * address form (identity on PC build).
   */
  SofdecAddressWord MPVLIB_ConvWorkAddr(SofdecAddressWord workAddress);

  /**
   * Address: 0x00AE7A50 (FUN_00AE7A50)
   *
   * What it does:
   * Applies optional work-address tag lane A when the corresponding runtime
   * flag is enabled.
   */
  SofdecAddressWord MPVLIB_ConvAddrPrimary(SofdecAddressWord address);

  /**
   * Address: 0x00AE7A70 (FUN_00AE7A70)
   *
   * What it does:
   * Applies optional work-address tag lane B when the corresponding runtime
   * flag is enabled.
   */
  SofdecAddressWord MPVLIB_ConvAddrSecondary(SofdecAddressWord address);

  /**
   * Address: 0x00AE7A90 (FUN_00AE7A90)
   *
   * What it does:
   * Normalizes an address into the high-bit tagged address domain used by MPV
   * runtime lanes.
   */
  std::uint32_t MPVLIB_ConvAddrWindow8(SofdecAddressWord address);

  /**
   * Address: 0x00AE7AA0 (FUN_00AE7AA0, _mpvlib_InitClip)
   *
   * What it does:
   * Initializes clip-table defaults and optionally mirrors them into caller
   * work memory.
   */
  std::int32_t* mpvlib_InitClip(std::int32_t* clipTableStorage);

  /**
   * Address: 0x00AE7AD0 (FUN_00AE7AD0, _mpvlib_InitClip0255)
   *
   * What it does:
   * Builds the canonical signed clip table [-384..639] with central
   * 0..255 identity lane.
   */
  int mpvlib_InitClip0255();

  /**
   * Address: 0x00AE7B10 (FUN_00AE7B10, _mpvlib_InitObjTbl)
   *
   * What it does:
   * Marks each allocated MPV work object slot as active in the object table.
   */
  void mpvlib_InitObjTbl();

  /**
   * Address: 0x00AE7B40 (FUN_00AE7B40, _mpvlib_InitDct)
   *
   * What it does:
   * Initializes DCT runtime kernels and scale tables in caller work memory.
   */
  int mpvlib_InitDct(moho::movie::MPVSharedWork* sharedWork);

  /**
   * Address: 0x00AE7B60 (FUN_00AE7B60, _mpvlib_InitWork)
   *
   * What it does:
   * Clears/aligned MPV work arena, seeds conceal workspace, and stores active
   * runtime lane pointers into global MPV work state.
   */
  std::int32_t* mpvlib_InitWork(int objectCount, SofdecAddressWord workMemoryBaseAddress);

  /**
   * Address: 0x00AE7BE0 (FUN_00AE7BE0, _MPV_Finish)
   *
   * What it does:
   * Finalizes MPV decode/conceal subsystems using active global work state.
   */
  int MPV_Finish();

  /**
   * Address: 0x00AE7C00 (FUN_00AE7C00, _MPV_Create)
   *
   * What it does:
   * Allocates one free MPV handle slot, initializes it, and creates the paired
   * MPVM2V runtime object.
   */
  int MPV_Create();

  /**
   * Address: 0x00AE7C40 (FUN_00AE7C40, _mpvlib_SearchFreeHn)
   *
   * What it does:
   * Scans the MPV handle table for a free slot marker and returns its address.
   */
  int mpvlib_SearchFreeHn();

  /**
   * Address: 0x00AE7C70 (FUN_00AE7C70, _mpvlib_InitHn)
   *
   * What it does:
   * Performs full per-handle initialization: object lanes, error state,
   * picture attributes, callback defaults, and stream hooks.
   */
  int mpvlib_InitHn(SofdecAddressWord handleAddress);

  /**
   * Address: 0x00AE7D60 (FUN_00AE7D60, _mpvlib_InitObj)
   *
   * What it does:
   * Binds VLC/clip/transform and internal scratch lanes for one MPV handle.
   */
  int mpvlib_InitObj(SofdecAddressWord handleAddress);

  /**
   * Address: 0x00AE7E70 (FUN_00AE7E70, _mpvlib_InitPicAtr)
   *
   * What it does:
   * Resets picture-attribute defaults used by MPEG picture decode paths.
   */
  int mpvlib_InitPicAtr(int pictureAttributesAddress);

  /**
   * Address: 0x00AE7F10 (FUN_00AE7F10, _mpvlib_InitDctPa)
   *
   * What it does:
   * Initializes per-handle DCT plane state and binds DCT count/scratch lanes.
   */
  int mpvlib_InitDctPa(SofdecAddressWord handleAddress);

  /**
   * Address: 0x00AE7F40 (FUN_00AE7F40, _MPV_GetDctCnt)
   *
   * What it does:
   * Reads two per-handle DCT counters into caller outputs.
   */
  int MPV_GetDctCnt(SofdecAddressWord handleAddress, int* outPrimaryCount, int* outSecondaryCount);

  /**
   * Address: 0x00AE7F60 (FUN_00AE7F60, _MPV_Destroy)
   *
   * What it does:
   * Validates and destroys one MPV handle lane, then marks it free.
   */
  int MPV_Destroy(SofdecAddressWord handleAddress);

  /**
   * Address: 0x00AE7FB0 (FUN_00AE7FB0, nullsub_48)
   *
   * What it does:
   * No-op range initializer hook retained for binary parity.
   */
  void mpvlib_NoOpInitializeRange(void* stateBaseAddress, int stateSizeBytes);

  /**
   * Address: 0x00AE7FC0 (FUN_00AE7FC0, _MPVCONCEAL_Finish)
   *
   * What it does:
   * No-op conceal teardown hook retained for binary parity.
   */
  int MPVCONCEAL_Finish(int concealStateBaseAddress, int concealStateSizeBytes);

  /**
   * Address: 0x00AE7FD0 (FUN_00AE7FD0, nullsub_26)
   *
   * What it does:
   * Default no-op condition callback used when condition slot 8 is null.
   */
  int mpvlib_DefaultConditionNoOp();

  /**
   * Address: 0x00AE7FE0 (FUN_00AE7FE0, _MPV_SetCond)
   *
   * What it does:
   * Sets one runtime condition callback either globally or per handle.
   */
  int MPV_SetCond(SofdecAddressWord handleAddress, int conditionIndex, int (*conditionCallback)());

  /**
   * Address: 0x00AE8060 (FUN_00AE8060, _mpvlib_SetCondAll)
   *
   * What it does:
   * Broadcasts one condition callback to all active MPV handle lanes.
   */
  int mpvlib_SetCondAll(int conditionIndex, int callbackAddress);

  /**
   * Address: 0x00AE80A0 (FUN_00AE80A0, _MPV_GetCond)
   *
   * What it does:
   * Gets one runtime condition callback from either global state or a handle.
   */
  int MPV_GetCond(SofdecAddressWord handleAddress, int conditionIndex, int* outCallbackAddress);

  /**
   * Address: 0x00AE8100 (FUN_00AE8100, _MPVLIB_CheckHn)
   *
   * What it does:
   * Validates that a handle exists and is currently allocated.
   */
  int MPVLIB_CheckHn(SofdecAddressWord handleAddress);

  /**
   * Address: 0x00AE8120 (FUN_00AE8120, _MPVHDEC_Init)
   *
   * What it does:
   * Initializes macroblock decode dispatch tables for normal and thumbnail
   * decode lanes.
   */
  void MPVHDEC_Init();

  /**
   * Address: 0x00AE8270 (FUN_00AE8270, _MPV_SetUsrSj)
   *
   * What it does:
   * Sets one user SJ stream slot (object/callback/context) for a handle.
   */
  std::int32_t* MPV_SetUsrSj(
    SofdecAddressWord handleAddress, int streamIndex, int streamObjectAddress, int streamCallbackAddress, int streamContextAddress
  );

  /**
   * Address: 0x00AE82A0 (FUN_00AE82A0, _MPV_SetPicUsrBuf)
   *
   * What it does:
   * Sets per-handle picture-user buffer/context and clears picture decode-state
   * latch.
   */
  std::int32_t* MPV_SetPicUsrBuf(SofdecAddressWord handleAddress, SofdecAddressWord userBufferAddress, int userBufferBytes);

  /**
   * Address: 0x00AE82D0 (FUN_00AE82D0, _MPV_GetPicUsr)
   *
   * What it does:
   * Reads per-handle picture-user buffer/decode-state fields.
   */
  int* MPV_GetPicUsr(SofdecAddressWord handleAddress, int* outUserBufferAddress, int* outDecodeState);

  /**
   * Address: 0x00AE8300 (FUN_00AE8300, _MPV_DecodePicAtrSj)
   *
   * What it does:
   * Decodes picture attributes from an SJ stream using delimiter recovery
   * semantics.
   */
  int MPV_DecodePicAtrSj(SofdecAddressWord handleAddress, moho::SofdecSjSupplyHandle* stream);

  /**
   * Address: 0x00AE84C0 (FUN_00AE84C0, _mpvhdec_GetCurDelim)
   *
   * What it does:
   * Reads current stream delimiter type from the active SJ chunk.
   */
  int mpvhdec_GetCurDelim(moho::SofdecSjSupplyHandle* stream);

  /**
   * Address: 0x00AE8510 (FUN_00AE8510, _MPV_DecodePicAtr)
   *
   * What it does:
   * Decodes picture attributes from a raw buffer range through SJ memory
   * wrapper stream.
   */
  int MPV_DecodePicAtr(SofdecAddressWord handleAddress, const int* pictureDataRange, int* outConsumedBytes);

  /**
   * Address: 0x00AEAB20 (FUN_00AEAB20, _MPV_DecodeFrmSj)
   *
   * What it does:
   * Decodes one frame from an SJ stream, refreshes exported picture attributes,
   * and reports recovery-counter deltas.
   */
  int MPV_DecodeFrmSj(SofdecAddressWord handleAddress, moho::SofdecSjSupplyHandle* stream, moho::movie::MPVFrameDecodeSession* frameSession);

  /**
   * Address: 0x00AE8570 (FUN_00AE8570, _mpvhdec_GetCodec)
   *
   * What it does:
   * Classifies codec lane for current chunk and caches result in handle state.
   */
  int mpvhdec_GetCodec(SofdecAddressWord handleAddress, moho::SjChunkRange* chunk);

  /**
   * Address: 0x00AE94C0 (FUN_00AE94C0, _mpvhdec_AnalyUd)
   *
   * What it does:
   * Scans user-data payload, forwards captured bytes to configured user lanes,
   * and applies sequence user-data directives when needed.
   */
  int mpvhdec_AnalyUd(std::int32_t* handleWords, std::uint8_t* userDataStart, int chunkSize);

  /**
   * Address: 0x00AE9650 (FUN_00AE9650, _mpvhdec_DecSeqUdsc)
   *
   * What it does:
   * Parses sequence user-data directives (`IDCPREC`, `STCCODE`) and updates
   * decoder kernel/table lane bindings.
   */
  int mpvhdec_DecSeqUdsc(std::int32_t* handleWords, const std::uint8_t* userDataStart, int consumedByteCount);

  /**
   * Address: 0x00AE9A10 (FUN_00AE9A10, _MPVHDEC_RecoverSj)
   *
   * What it does:
   * Advances/realigns SJ stream to matching delimiter mask with recovery
   * counters.
   */
  int MPVHDEC_RecoverSj(SofdecAddressWord handleAddress, int expectedDelimiterMask, moho::SofdecSjSupplyHandle* stream);

  /**
   * Address: 0x00AE9AB0 (FUN_00AE9AB0, _MPV_MoveChunk)
   *
   * What it does:
   * Moves one stream chunk between lanes and returns moved byte count.
   */
  int MPV_MoveChunk(moho::SofdecSjSupplyHandle* stream, int lane, int byteCount);

  /**
   * Address: 0x00AE78E0 (FUN_00AE78E0, _MPV_IsConformable)
   *
   * What it does:
   * Checks whether one chunk is conformable for MPV-vs-M2V dispatch by
   * probing sequence/user-data delimiter ordering.
   */
  int MPV_IsConformable(const std::uint8_t* bitstreamCursor, int scanLengthBytes);

  /**
   * Address: 0x00AE9F10 (FUN_00AE9F10, _MPV_CheckDelim)
   *
   * What it does:
   * Classifies one 4-byte start-code word into MPV delimiter categories.
   */
  int MPV_CheckDelim(const std::uint8_t* bitstreamCursor);

  /**
   * Address: 0x00AE9FB0 (FUN_00AE9FB0, _MPV_BsearchDelim)
   *
   * What it does:
   * Scans backward from one-past-end cursor for a delimiter matching mask.
   */
  std::uint8_t* MPV_BsearchDelim(std::uint8_t* bitstreamCursor, unsigned int scanLengthBytes, int delimiterMask);

  /**
   * Address: 0x00AEA040 (FUN_00AEA040, _MPV_SearchDelim)
   *
   * What it does:
   * Scans forward across a byte range and returns first matching delimiter.
   */
  std::uint8_t* MPV_SearchDelim(const std::uint8_t* bitstreamCursor, int scanLengthBytes, int delimiterMask);

  /**
   * Address: 0x00AF63A0 (FUN_00AF63A0, _MPVVLC_Init)
   *
   * What it does:
   * Initializes all static MPV VLC tables and optionally builds runtime VLC
   * state for a provided setup context.
   *
   * `runtimeWorkBase` is pushed by the sole call site (`MPV_Init` at
   * 0x00AE79A3) but never read by the body, which reads only `[esp+arg_0]`.
   * Kept so the recovered call matches the binary's two-argument form.
   */
  int MPVVLC_Init(int vlcContextBase, int runtimeWorkBase);

  /**
   * Address: 0x00AF63E0 (FUN_00AF63E0, _mpvvlc_InitMbai)
   *
   * What it does:
   * Initializes I/P/B-picture MBAI seed tables.
   */
  std::uint16_t* mpvvlc_InitMbai();

  /**
   * Address: 0x00AF63F0 (FUN_00AF63F0, _mpvvlc_InitMbaiIpic)
   *
   * What it does:
   * Seeds I-picture MBAI VLC tables (`mpvvlt_mbai_i_0` and
   * `mpvvlt_mbai_i_1`).
   */
  int mpvvlc_InitMbaiIpic();

  /**
   * Address: 0x00AF6630 (FUN_00AF6630, _mpvvlc_InitMbaiPpic)
   *
   * What it does:
   * Seeds P-picture MBAI VLC tables (`mpvvlt_mbai_p_0` and
   * `mpvvlt_mbai_p_1`).
   */
  std::uint16_t* mpvvlc_InitMbaiPpic();

  /**
   * Address: 0x00AF68D0 (FUN_00AF68D0, _mpvvlc_InitMbaiBpic)
   *
   * What it does:
   * Seeds B-picture MBAI VLC tables (`mpvvlt_mbai_b_0` and
   * `mpvvlt_mbai_b_1`).
   */
  std::uint16_t* mpvvlc_InitMbaiBpic();

  /**
   * Address: 0x00AF6B80 (FUN_00AF6B80, _mpvvlc_InitMbType)
   *
   * What it does:
   * Initializes both P-picture and B-picture MB-type VLC seed tables.
   */
  int mpvvlc_InitMbType();

  /**
   * Address: 0x00AF6B90 (FUN_00AF6B90, _mpvvlc_InitMbTypePpic)
   *
   * What it does:
   * Seeds the static P-picture MB-type VLC table.
   */
  int mpvvlc_InitMbTypePpic();

  /**
   * Address: 0x00AF6C00 (FUN_00AF6C00, _mpvvlc_InitMbTypeBpic)
   *
   * What it does:
   * Seeds the static B-picture MB-type VLC table.
   */
  int mpvvlc_InitMbTypeBpic();

  /**
   * Address: 0x00AF6CC0 (FUN_00AF6CC0, _mpvvlc_InitMotion)
   *
   * What it does:
   * Seeds motion-vector VLC tables (`mpvvlt_motion_0` and
   * `mpvvlt_motion_1`).
   */
  int mpvvlc_InitMotion();

  /**
   * Address: 0x00AF6E30 (FUN_00AF6E30, _mpvvlc_InitCbp)
   *
   * What it does:
   * Initializes the complete CBP VLC table by chaining two seed segments.
   */
  std::uint32_t* mpvvlc_InitCbp();

  /**
   * Address: 0x00AF6E50 (FUN_00AF6E50, _mpvvlc_InitCbpSub1)
   *
   * What it does:
   * Seeds the first contiguous CBP VLC segment and returns the next write
   * cursor.
   */
  std::uint32_t* mpvvlc_InitCbpSub1(std::uint32_t* cbpTable);

  /**
   * Address: 0x00AF6F90 (FUN_00AF6F90, _mpvvlc_InitCbpSub2)
   *
   * What it does:
   * Seeds trailing CBP VLC segments and returns the final write cursor.
   */
  std::uint32_t* mpvvlc_InitCbpSub2(std::uint32_t* cbpCursor);

  /**
   * Address: 0x00AF7190 (FUN_00AF7190, _mpvvlc_InitDcSiz)
   *
   * What it does:
   * Initializes primary and secondary Y/C DC-size VLC seed tables.
   */
  int mpvvlc_InitDcSiz();

  /**
   * Address: 0x00AF71B0 (FUN_00AF71B0, _mpvvlc_InitDcSizY)
   *
   * What it does:
   * Seeds primary Y DC-size VLC table entries.
   */
  int mpvvlc_InitDcSizY();

  /**
   * Address: 0x00AF7260 (FUN_00AF7260, _mpvvlc_InitDcSizC)
   *
   * What it does:
   * Seeds primary C DC-size VLC table entries.
   */
  int mpvvlc_InitDcSizC();

  /**
   * Address: 0x00AF72F0 (FUN_00AF72F0, _mpvvlc2_InitDcSizY)
   *
   * What it does:
   * Seeds secondary Y DC-size VLC table entries.
   */
  int mpvvlc2_InitDcSizY();

  /**
   * Address: 0x00AF73B0 (FUN_00AF73B0, _mpvvlc2_InitDcSizC)
   *
   * What it does:
   * Seeds secondary C DC-size VLC table entries.
   */
  int mpvvlc2_InitDcSizC();

  /**
   * Address: 0x00AF7470 (FUN_00AF7470, _mpvvlc_InitRunLevel)
   *
   * What it does:
   * Thin run-level init thunk that forwards into the concrete 8-bit table
   * initializer.
   */
  int mpvvlc_InitRunLevel();

  /**
   * Address: 0x00AF7480 (FUN_00AF7480, _mpvvlc_InitIntRunLevel)
   *
   * What it does:
   * Seeds the 8-bit run-level VLC table with fixed entries and compact value
   * runs used by MPV decode setup.
   */
  int mpvvlc_InitIntRunLevel();

  /**
   * Address: 0x00AF7620 (FUN_00AF7620, _mpvvlc_SetDflPtr)
   *
   * What it does:
   * Rebinds active VLC pointer lanes to their default static table roots.
   */
  void mpvvlc_SetDflPtr();

  /**
   * Address: 0x00AF7730 (FUN_00AF7730, _mpvvlc_SetVlcRunLevel)
   *
   * What it does:
   * Carves run-level VLC lanes inside the runtime setup arena and copies
   * static defaults into each lane.
   */
  int mpvvlc_SetVlcRunLevel(int runLevelStateBase);

  /**
   * Address: 0x00AF77E0 (FUN_00AF77E0, _mpvvlc_SetVlcDcSiz)
   *
   * What it does:
   * Allocates Y/C DC-size VLC lanes in the setup arena and copies their
   * default decode tables.
   */
  int mpvvlc_SetVlcDcSiz(int runLevelState);

  /**
   * Address: 0x00AF7820 (FUN_00AF7820, _mpvvlc_SetVlcMotion)
   *
   * What it does:
   * Writes motion-vector VLC tables into the setup arena and returns the next
   * free cursor for downstream setup lanes.
   */
  int mpvvlc_SetVlcMotion(int runLevelState);

  /**
   * Address: 0x00AF7860 (FUN_00AF7860, _mpvvlc_SetVlcMbType)
   *
   * What it does:
   * Allocates and seeds P/B macroblock-type VLC tables, returning the
   * remaining setup cursor after both tables are copied.
   */
  int mpvvlc_SetVlcMbType(int runLevelState);

  /**
   * Address: 0x00AF7700 (FUN_00AF7700, _mpvvlc_SetupVlc)
   *
   * What it does:
   * Builds VLC runtime state by chaining run-level, DC-size, motion, and
   * macroblock-type setup lanes.
   */
  int mpvvlc_SetupVlc(int vlcContextBase);
}
