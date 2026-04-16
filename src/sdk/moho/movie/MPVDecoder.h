#pragma once

#include <cstddef>
#include <cstdint>

namespace moho::movie
{
  struct MPVDecoderContextPrefix;
  struct MPVDecoderScanContext;
  struct MPVSjStream;
  struct MPVPredictionKernelState;

  using MPVDecodeMacroblockFn = void(__cdecl*)(MPVDecoderContextPrefix*);
  using MPVInterpolationKernelFn = int(__cdecl*)(MPVPredictionKernelState*);

  struct MPVBitstreamState
  {
    std::uint32_t bitWindowPrimary;   // +0x00
    std::uint32_t bitWindowSecondary; // +0x04
    int bitCount;                     // +0x08
    std::uint8_t* byteCursor;         // +0x0C
  };

  static_assert(sizeof(MPVBitstreamState) == 0x10, "MPVBitstreamState size must be 0x10");
  static_assert(offsetof(MPVBitstreamState, bitCount) == 0x08, "MPVBitstreamState::bitCount offset must be 0x08");
  static_assert(offsetof(MPVBitstreamState, byteCursor) == 0x0C, "MPVBitstreamState::byteCursor offset must be 0x0C");

  struct MPVSjChunk
  {
    std::uint8_t* data; // +0x00
    int size;           // +0x04
  };

  static_assert(sizeof(MPVSjChunk) == 0x08, "MPVSjChunk size must be 0x08");

  struct MPVFrameDecodeSession
  {
    std::int32_t decodeControlWords[9]; // +0x00
    int pictureAttributesAddress;       // +0x24
    int recoverEventDelta;              // +0x28
    int recoverConditionDelta;          // +0x2C
  };

  static_assert(sizeof(MPVFrameDecodeSession) == 0x30, "MPVFrameDecodeSession size must be 0x30");

  struct MPVBlockWriteTarget
  {
    std::uint8_t* pixels; // +0x00
    int stride;           // +0x04
  };

  static_assert(sizeof(MPVBlockWriteTarget) == 0x08, "MPVBlockWriteTarget size must be 0x08");

  struct MPVCopyDestinationSet
  {
    std::uint8_t* block0Base;   // +0x00
    MPVBlockWriteTarget blocks[6]; // +0x04
  };

  static_assert(sizeof(MPVCopyDestinationSet) == 0x34, "MPVCopyDestinationSet size must be 0x34");
  static_assert(offsetof(MPVCopyDestinationSet, blocks) == 0x04, "MPVCopyDestinationSet::blocks offset must be 0x04");

  struct MPVBlockSourceSet
  {
    int sampleBaseBias;              // +0x00
    std::int16_t* sampleAddressLut;  // +0x04
    std::uint8_t* forwardSamples;    // +0x08
    std::uint8_t* backwardSamples;   // +0x0C
  };

  static_assert(sizeof(MPVBlockSourceSet) == 0x10, "MPVBlockSourceSet size must be 0x10");

  struct MPVMacroblockOffsets
  {
    int lumaOffset;          // +0x00
    int chromaUOffset;       // +0x04
    int chromaVOffset;       // +0x08
    std::int16_t lumaStride; // +0x0C
    std::int16_t chromaStride; // +0x0E
  };

  static_assert(sizeof(MPVMacroblockOffsets) == 0x10, "MPVMacroblockOffsets size must be 0x10");

  struct MPVSpatialDelta
  {
    int luma;   // +0x00
    int chroma; // +0x04
  };

  static_assert(sizeof(MPVSpatialDelta) == 0x08, "MPVSpatialDelta size must be 0x08");

  struct MPVPredictionKernelState
  {
    std::int32_t reserved_00[6]; // +0x00
    int destinationBlockBase;    // +0x18
    std::int32_t reserved_1C;    // +0x1C
    int destinationStride;       // +0x20
    int sourcePrimary;           // +0x24
    int sourceSecondary;         // +0x28
  };

  static_assert(offsetof(MPVPredictionKernelState, destinationBlockBase) == 0x18, "MPVPredictionKernelState::destinationBlockBase offset must be 0x18");
  static_assert(offsetof(MPVPredictionKernelState, destinationStride) == 0x20, "MPVPredictionKernelState::destinationStride offset must be 0x20");
  static_assert(offsetof(MPVPredictionKernelState, sourcePrimary) == 0x24, "MPVPredictionKernelState::sourcePrimary offset must be 0x24");
  static_assert(offsetof(MPVPredictionKernelState, sourceSecondary) == 0x28, "MPVPredictionKernelState::sourceSecondary offset must be 0x28");
  static_assert(sizeof(MPVPredictionKernelState) == 0x2C, "MPVPredictionKernelState size must be 0x2C");

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

  static_assert(offsetof(MPVPredictionVectorSet, decodeConfig) == 0x00, "MPVPredictionVectorSet::decodeConfig offset must be 0x00");
  static_assert(offsetof(MPVPredictionVectorSet, predictorX) == 0x10, "MPVPredictionVectorSet::predictorX offset must be 0x10");
  static_assert(offsetof(MPVPredictionVectorSet, predictorY) == 0x14, "MPVPredictionVectorSet::predictorY offset must be 0x14");
  static_assert(offsetof(MPVPredictionVectorSet, horizontalDelta) == 0x18, "MPVPredictionVectorSet::horizontalDelta offset must be 0x18");
  static_assert(offsetof(MPVPredictionVectorSet, verticalDelta) == 0x1C, "MPVPredictionVectorSet::verticalDelta offset must be 0x1C");
  static_assert(sizeof(MPVPredictionVectorSet) == 0x24, "MPVPredictionVectorSet size must be 0x24");
  static_assert(sizeof(MPVPredictionVectorSet::MPVMotionDecodeConfig) == 0x10, "MPVMotionDecodeConfig size must be 0x10");

  struct MPVMotionState
  {
    std::int32_t reserved[4];   // +0x00
    std::int32_t predictors[4]; // +0x10
  };

  static_assert(offsetof(MPVMotionState, predictors) == 0x10, "MPVMotionState::predictors offset must be 0x10");
  static_assert(sizeof(MPVMotionState) == 0x20, "MPVMotionState size must be 0x20");

  struct MPVDecoderContextPrefix
  {
    std::uint8_t reserved_0000[0x40];
    int lumaBaseAddress; // +0x40
    std::uint8_t reserved_0044[0xCC - 0x44];
    MPVPredictionKernelState predictionKernelState; // +0xCC
    std::uint8_t reserved_00F8[0x110 - 0xF8];

    MPVBlockSourceSet blockSources;       // +0x110
    MPVCopyDestinationSet copyTargets;    // +0x120

    std::uint8_t reserved_0154[0x19C - 0x154];
    int interpolationParity; // +0x19C
    std::uint8_t reserved_01A0[0x1D8 - 0x1A0];
    int macroblocksPerRow;    // +0x1D8
    int macroblockRowsCount;  // +0x1DC
    std::uint8_t reserved_01E0[0x264 - 0x1E0];

    MPVMacroblockOffsets forwardOffsets;   // +0x264 (+612)
    MPVMacroblockOffsets backwardOffsets;  // +0x274 (+628)

    std::uint8_t reserved_0284[0x294 - 0x284];
    int planeBase0; // +0x294 (+660)
    int planeBase1; // +0x298 (+664)
    int planeBase2; // +0x29C (+668)
    std::uint8_t reserved_02A0[0x2A2 - 0x2A0];
    std::int16_t planeBase2Stride; // +0x2A2 (+674)

    std::uint8_t reserved_02A4[0x2D4 - 0x2A4];
    MPVDecodeMacroblockFn decodeSkippedBpicMacroblock; // +0x2D4 (+724)
    std::uint8_t reserved_02D8[0x2F0 - 0x2D8];
    MPVPredictionVectorSet forwardPredictionVector;   // +0x2F0 (+752)
    MPVPredictionVectorSet backwardPredictionVector;  // +0x314 (+788)

    int macroblockLinearIndex; // +0x338 (+824)
    int macroblockRow;         // +0x33C (+828)
    int macroblockColumn;      // +0x340 (+832)

    std::uint8_t reserved_0344[0x34C - 0x344];
    int predictionSignState; // +0x34C (+844)
    std::int32_t dcPredictorY;  // +0x350
    std::int32_t dcPredictorCb; // +0x354
    std::int32_t dcPredictorCr; // +0x358
    std::uint8_t reserved_035C[0x3A0 - 0x35C];
    std::int16_t intraCopyAddressLut[384]; // +0x3A0 .. +0x69F
  };

  static_assert(offsetof(MPVDecoderContextPrefix, blockSources) == 0x110, "MPVDecoderContextPrefix::blockSources offset must be 0x110");
  static_assert(offsetof(MPVDecoderContextPrefix, copyTargets) == 0x120, "MPVDecoderContextPrefix::copyTargets offset must be 0x120");
  static_assert(offsetof(MPVDecoderContextPrefix, interpolationParity) == 0x19C, "MPVDecoderContextPrefix::interpolationParity offset must be 0x19C");
  static_assert(offsetof(MPVDecoderContextPrefix, macroblocksPerRow) == 0x1D8, "MPVDecoderContextPrefix::macroblocksPerRow offset must be 0x1D8");
  static_assert(offsetof(MPVDecoderContextPrefix, forwardOffsets) == 0x264, "MPVDecoderContextPrefix::forwardOffsets offset must be 0x264");
  static_assert(offsetof(MPVDecoderContextPrefix, backwardOffsets) == 0x274, "MPVDecoderContextPrefix::backwardOffsets offset must be 0x274");
  static_assert(offsetof(MPVDecoderContextPrefix, planeBase0) == 0x294, "MPVDecoderContextPrefix::planeBase0 offset must be 0x294");
  static_assert(offsetof(MPVDecoderContextPrefix, planeBase2Stride) == 0x2A2, "MPVDecoderContextPrefix::planeBase2Stride offset must be 0x2A2");
  static_assert(offsetof(MPVDecoderContextPrefix, decodeSkippedBpicMacroblock) == 0x2D4, "MPVDecoderContextPrefix::decodeSkippedBpicMacroblock offset must be 0x2D4");
  static_assert(offsetof(MPVDecoderContextPrefix, forwardPredictionVector) == 0x2F0, "MPVDecoderContextPrefix::forwardPredictionVector offset must be 0x2F0");
  static_assert(offsetof(MPVDecoderContextPrefix, backwardPredictionVector) == 0x314, "MPVDecoderContextPrefix::backwardPredictionVector offset must be 0x314");
  static_assert(offsetof(MPVDecoderContextPrefix, macroblockLinearIndex) == 0x338, "MPVDecoderContextPrefix::macroblockLinearIndex offset must be 0x338");
  static_assert(offsetof(MPVDecoderContextPrefix, predictionSignState) == 0x34C, "MPVDecoderContextPrefix::predictionSignState offset must be 0x34C");
  static_assert(offsetof(MPVDecoderContextPrefix, dcPredictorY) == 0x350, "MPVDecoderContextPrefix::dcPredictorY offset must be 0x350");
  static_assert(offsetof(MPVDecoderContextPrefix, intraCopyAddressLut) == 0x3A0, "MPVDecoderContextPrefix::intraCopyAddressLut offset must be 0x3A0");
  static_assert(sizeof(MPVDecoderContextPrefix) == 0x6A0, "MPVDecoderContextPrefix size must be 0x6A0");

  struct MPVDecoderRuntimeStats
  {
    std::uint8_t reserved_0000[0x13AC];
    int motionClampCounter; // +0x13AC
  };

  static_assert(offsetof(MPVDecoderRuntimeStats, motionClampCounter) == 0x13AC, "MPVDecoderRuntimeStats::motionClampCounter offset must be 0x13AC");

  using MPVDecodeReadKernelFn = std::uint8_t(__cdecl*)(MPVDecoderScanContext* decoderContext, void* decodeState);
  using MPVDecodeFinalizeFlagsFn = void(__cdecl*)(std::uint8_t* flags);
  using MPVDecodeContextFn = void(__cdecl*)(MPVDecoderScanContext* decoderContext);
  using MPVDecodeSkipRunFn = void(__cdecl*)(MPVDecoderScanContext* decoderContext, unsigned int skipCount);
  using MPVDecoderServiceFn = void(__cdecl*)(int serviceToken);

  struct MPVDecoderScanContext
  {
    MPVBitstreamState bitstreamState; // +0x00
    std::uint8_t reserved_0010[0x60 - 0x10];
    int decodeCurrentSource; // +0x60
    int decodeWorkBase;      // +0x64
    int decodeBitstreamWord; // +0x68
    int decodeHuffmanPrimary;   // +0x6C
    int decodeHuffmanSecondary; // +0x70
    int decodePhase;            // +0x74
    std::uint8_t decodeFlags[6]; // +0x78
    std::uint8_t reserved_007E[0xA0 - 0x7E];
    int decodeSignLadder; // +0xA0
    std::uint8_t reserved_00A4[0x1AC - 0xA4];
    int serviceReloadInterval; // +0x1AC
    MPVDecoderServiceFn serviceCallback; // +0x1B0
    int serviceCallbackToken; // +0x1B4
    std::uint8_t reserved_01B8[0x1D8 - 0x1B8];
    int macroblocksPerRow;   // +0x1D8
    int macroblockRowsCount; // +0x1DC
    std::uint8_t reserved_01E0[0x2C4 - 0x1E0];
    MPVDecodeSkipRunFn decodeSkipRun; // +0x2C4
    MPVDecodeContextFn decodeIntraMacroblock; // +0x2C8
    MPVDecodeContextFn decodeResidualMacroblock; // +0x2CC
    MPVDecodeContextFn decodePostIntraMacroblock; // +0x2D0
    MPVDecodeContextFn decodePredictedModes[4]; // +0x2D4 .. +0x2E3
    MPVDecodeFinalizeFlagsFn decodeFinalizeIntra;     // +0x2E4
    MPVDecodeFinalizeFlagsFn decodeFinalizePredicted; // +0x2E8
    int decodeBitWindow; // +0x2EC (also quant scale in MB decode paths)
    MPVPredictionVectorSet forwardPredictionVector;  // +0x2F0
    MPVPredictionVectorSet backwardPredictionVector; // +0x314
    int macroblockLinearIndex; // +0x338
    int macroblockRow;         // +0x33C
    int macroblockColumn;      // +0x340
    int macroblockLinearLimit; // +0x344
    int macroblockTypeFlags;   // +0x348
    int predictionSignState; // +0x34C
    std::int32_t dcPredictorY;  // +0x350
    std::int32_t dcPredictorCb; // +0x354
    std::int32_t dcPredictorCr; // +0x358
    std::uint8_t reserved_035C[0x6A0 - 0x35C];
    std::uint8_t scanScratch0[0x100]; // +0x6A0
    std::uint8_t scanScratch1[0x100]; // +0x7A0
    std::uint8_t scanScratch2[0x100]; // +0x8A0
    std::uint8_t scanScratch3[0x100]; // +0x9A0
    std::uint8_t scanScratch4[0x100]; // +0xAA0
    std::uint8_t scanScratch5[0x100]; // +0xBA0
    std::uint8_t decodeWorkScratchIntra[0x40];      // +0xCA0
    std::uint8_t decodeWorkScratchPredicted[0x258]; // +0xCE0
    std::uint8_t reserved_0F38[0x1320 - 0x0F38];
    int recoverNeededFlag; // +0x1320
    std::uint8_t reserved_1324[0x1328 - 0x1324];
    MPVSjChunk activeChunk; // +0x1328
    int sliceBitAlignment; // +0x1330
    std::uint8_t reserved_1334[0x1338 - 0x1334];
    MPVDecodeReadKernelFn decodeReadKernelIntra;     // +0x1338
    MPVDecodeReadKernelFn decodeReadKernelPredicted; // +0x133C
    std::uint8_t reserved_1340[0x1344 - 0x1340];
    int serviceCountdown; // +0x1344
    int decodeTablePrimary;   // +0x1348
    int decodeTableSecondary; // +0x134C
    std::uint8_t reserved_1350[0x1398 - 0x1350];
    MPVDecodeContextFn macroblockDiscontinuityHandler; // +0x1398
    int lastDecodedMacroblockIndex; // +0x139C
    std::uint8_t reserved_13A0[0x13AC - 0x13A0];
    int motionClampCounter; // +0x13AC
  };

  static_assert(offsetof(MPVDecoderScanContext, bitstreamState) == 0x00, "MPVDecoderScanContext::bitstreamState offset must be 0x00");
  static_assert(offsetof(MPVDecoderScanContext, decodeCurrentSource) == 0x60, "MPVDecoderScanContext::decodeCurrentSource offset must be 0x60");
  static_assert(offsetof(MPVDecoderScanContext, decodeWorkBase) == 0x64, "MPVDecoderScanContext::decodeWorkBase offset must be 0x64");
  static_assert(offsetof(MPVDecoderScanContext, decodeFlags) == 0x78, "MPVDecoderScanContext::decodeFlags offset must be 0x78");
  static_assert(offsetof(MPVDecoderScanContext, decodeSignLadder) == 0xA0, "MPVDecoderScanContext::decodeSignLadder offset must be 0xA0");
  static_assert(offsetof(MPVDecoderScanContext, serviceReloadInterval) == 0x1AC, "MPVDecoderScanContext::serviceReloadInterval offset must be 0x1AC");
  static_assert(offsetof(MPVDecoderScanContext, macroblocksPerRow) == 0x1D8, "MPVDecoderScanContext::macroblocksPerRow offset must be 0x1D8");
  static_assert(offsetof(MPVDecoderScanContext, decodeSkipRun) == 0x2C4, "MPVDecoderScanContext::decodeSkipRun offset must be 0x2C4");
  static_assert(offsetof(MPVDecoderScanContext, decodeFinalizeIntra) == 0x2E4, "MPVDecoderScanContext::decodeFinalizeIntra offset must be 0x2E4");
  static_assert(offsetof(MPVDecoderScanContext, decodeFinalizePredicted) == 0x2E8, "MPVDecoderScanContext::decodeFinalizePredicted offset must be 0x2E8");
  static_assert(offsetof(MPVDecoderScanContext, decodeBitWindow) == 0x2EC, "MPVDecoderScanContext::decodeBitWindow offset must be 0x2EC");
  static_assert(offsetof(MPVDecoderScanContext, forwardPredictionVector) == 0x2F0, "MPVDecoderScanContext::forwardPredictionVector offset must be 0x2F0");
  static_assert(offsetof(MPVDecoderScanContext, backwardPredictionVector) == 0x314, "MPVDecoderScanContext::backwardPredictionVector offset must be 0x314");
  static_assert(offsetof(MPVDecoderScanContext, macroblockLinearIndex) == 0x338, "MPVDecoderScanContext::macroblockLinearIndex offset must be 0x338");
  static_assert(offsetof(MPVDecoderScanContext, macroblockLinearLimit) == 0x344, "MPVDecoderScanContext::macroblockLinearLimit offset must be 0x344");
  static_assert(offsetof(MPVDecoderScanContext, macroblockTypeFlags) == 0x348, "MPVDecoderScanContext::macroblockTypeFlags offset must be 0x348");
  static_assert(offsetof(MPVDecoderScanContext, predictionSignState) == 0x34C, "MPVDecoderScanContext::predictionSignState offset must be 0x34C");
  static_assert(offsetof(MPVDecoderScanContext, dcPredictorY) == 0x350, "MPVDecoderScanContext::dcPredictorY offset must be 0x350");
  static_assert(offsetof(MPVDecoderScanContext, scanScratch0) == 0x6A0, "MPVDecoderScanContext::scanScratch0 offset must be 0x6A0");
  static_assert(offsetof(MPVDecoderScanContext, scanScratch5) == 0xBA0, "MPVDecoderScanContext::scanScratch5 offset must be 0xBA0");
  static_assert(offsetof(MPVDecoderScanContext, decodeWorkScratchIntra) == 0xCA0, "MPVDecoderScanContext::decodeWorkScratchIntra offset must be 0xCA0");
  static_assert(offsetof(MPVDecoderScanContext, decodeWorkScratchPredicted) == 0xCE0, "MPVDecoderScanContext::decodeWorkScratchPredicted offset must be 0xCE0");
  static_assert(offsetof(MPVDecoderScanContext, recoverNeededFlag) == 0x1320, "MPVDecoderScanContext::recoverNeededFlag offset must be 0x1320");
  static_assert(offsetof(MPVDecoderScanContext, activeChunk) == 0x1328, "MPVDecoderScanContext::activeChunk offset must be 0x1328");
  static_assert(offsetof(MPVDecoderScanContext, sliceBitAlignment) == 0x1330, "MPVDecoderScanContext::sliceBitAlignment offset must be 0x1330");
  static_assert(offsetof(MPVDecoderScanContext, decodeReadKernelIntra) == 0x1338, "MPVDecoderScanContext::decodeReadKernelIntra offset must be 0x1338");
  static_assert(offsetof(MPVDecoderScanContext, decodeReadKernelPredicted) == 0x133C, "MPVDecoderScanContext::decodeReadKernelPredicted offset must be 0x133C");
  static_assert(offsetof(MPVDecoderScanContext, serviceCountdown) == 0x1344, "MPVDecoderScanContext::serviceCountdown offset must be 0x1344");
  static_assert(offsetof(MPVDecoderScanContext, decodeTablePrimary) == 0x1348, "MPVDecoderScanContext::decodeTablePrimary offset must be 0x1348");
  static_assert(offsetof(MPVDecoderScanContext, decodeTableSecondary) == 0x134C, "MPVDecoderScanContext::decodeTableSecondary offset must be 0x134C");
  static_assert(offsetof(MPVDecoderScanContext, macroblockDiscontinuityHandler) == 0x1398, "MPVDecoderScanContext::macroblockDiscontinuityHandler offset must be 0x1398");
  static_assert(offsetof(MPVDecoderScanContext, lastDecodedMacroblockIndex) == 0x139C, "MPVDecoderScanContext::lastDecodedMacroblockIndex offset must be 0x139C");

  /**
   * Address: 0x00C0C000 (FUN_00C0C000)
   *
   * MPV decoder intra macroblock path.
   *
   * What it does:
   * Computes destination plane pointers for the current MB and writes the six
   * intra 8x8 blocks through the LUT-based luma copy path.
   */
  int MPVUMC_Intra(MPVDecoderContextPrefix* context);

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
    MPVDecoderContextPrefix* context,
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
  int MPVUMC_Forward(MPVDecoderContextPrefix* context);

  /**
   * Address: 0x00C0C250 (FUN_00C0C250)
   *
   * What it does:
   * Recovers backward-predicted MB samples then writes frame420 blocks.
   */
  int MPVUMC_Backward(MPVDecoderContextPrefix* context);

  /**
   * Address: 0x00C0C2E0 (FUN_00C0C2E0)
   *
   * What it does:
   * Recovers forward+backward MB samples and writes bi-directional frame420
   * blend blocks.
   */
  int MPVUMC_BiDirect(MPVDecoderContextPrefix* context);

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
  int MPVUMC_BpicSkipped(MPVDecoderContextPrefix* context, int skippedMacroblockCount);

  /**
   * Address: 0x00C0C9B0 (FUN_00C0C9B0)
   *
   * What it does:
   * Rewinds MB address by skip count and copies forward prediction lanes into
   * backward lanes for each skipped P-picture MB.
   */
  int MPVUMC_PpicSkipped(MPVDecoderContextPrefix* context, int skippedMacroblockCount);

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
    const MPVDecoderContextPrefix* context, const MPVMacroblockOffsets& blockOffsets, MPVSpatialDelta& outDelta
  );

  /**
   * Address: 0x00C0CCB0 (FUN_00C0CCB0)
   *
   * What it does:
   * Decrements MB address by a skip amount and wraps row/column indices when
   * the column crosses the left boundary.
   */
  MPVDecoderContextPrefix* mpvumc_SubMbadr(MPVDecoderContextPrefix* context, int decrement);

  /**
   * Address: 0x00C0CD10 (FUN_00C0CD10)
   *
   * What it does:
   * Increments MB address by one and wraps row/column indices when the column
   * reaches row width.
   */
  MPVDecoderContextPrefix* mpvumc_IncreMbadr(MPVDecoderContextPrefix* context);

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
  MPVDecoderContextPrefix* MPVDEC_ResetDc(MPVDecoderContextPrefix* context);

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
  int MPVDEC_DecIpicMb(MPVDecoderScanContext* context, MPVSjStream* stream);

  /**
   * Address: 0x00C0D1D0 (FUN_00C0D1D0)
   *
   * What it does:
   * Decodes P-picture macroblocks from the current slice chunk stream.
   */
  int MPVDEC_DecPpicMb(MPVDecoderScanContext* context, MPVSjStream* stream);

  /**
   * Address: 0x00C0DA80 (FUN_00C0DA80)
   *
   * What it does:
   * Decodes B-picture macroblocks from the current slice chunk stream,
   * including MBAI/MB-type/CBP/motion paths and chunk refill handling.
   */
  int MPVDEC_DecBpicMb(MPVDecoderScanContext* context, MPVSjStream* stream);
} // namespace moho::movie

extern "C"
{
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
  int MPVLIB_ConvWorkAddr(int workAddress);

  /**
   * Address: 0x00AE7A50 (FUN_00AE7A50)
   *
   * What it does:
   * Applies optional work-address tag lane A when the corresponding runtime
   * flag is enabled.
   */
  int MPVLIB_ConvAddrPrimary(int address);

  /**
   * Address: 0x00AE7A70 (FUN_00AE7A70)
   *
   * What it does:
   * Applies optional work-address tag lane B when the corresponding runtime
   * flag is enabled.
   */
  int MPVLIB_ConvAddrSecondary(int address);

  /**
   * Address: 0x00AE7A90 (FUN_00AE7A90)
   *
   * What it does:
   * Normalizes an address into the high-bit tagged address domain used by MPV
   * runtime lanes.
   */
  std::uint32_t MPVLIB_ConvAddrWindow8(int address);

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
  int mpvlib_InitDct(int runtimeWorkBase);

  /**
   * Address: 0x00AE7B60 (FUN_00AE7B60, _mpvlib_InitWork)
   *
   * What it does:
   * Clears/aligned MPV work arena, seeds conceal workspace, and stores active
   * runtime lane pointers into global MPV work state.
   */
  std::int32_t* mpvlib_InitWork(int objectCount, int workMemoryBaseAddress);

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
  int mpvlib_InitHn(int handleAddress);

  /**
   * Address: 0x00AE7D60 (FUN_00AE7D60, _mpvlib_InitObj)
   *
   * What it does:
   * Binds VLC/clip/transform and internal scratch lanes for one MPV handle.
   */
  int mpvlib_InitObj(int handleAddress);

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
  int mpvlib_InitDctPa(int handleAddress);

  /**
   * Address: 0x00AE7F40 (FUN_00AE7F40, _MPV_GetDctCnt)
   *
   * What it does:
   * Reads two per-handle DCT counters into caller outputs.
   */
  int MPV_GetDctCnt(int handleAddress, int* outPrimaryCount, int* outSecondaryCount);

  /**
   * Address: 0x00AE7F60 (FUN_00AE7F60, _MPV_Destroy)
   *
   * What it does:
   * Validates and destroys one MPV handle lane, then marks it free.
   */
  int MPV_Destroy(int handleAddress);

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
  int MPV_SetCond(int handleAddress, int conditionIndex, int (*conditionCallback)());

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
  int MPV_GetCond(int handleAddress, int conditionIndex, int* outCallbackAddress);

  /**
   * Address: 0x00AE8100 (FUN_00AE8100, _MPVLIB_CheckHn)
   *
   * What it does:
   * Validates that a handle exists and is currently allocated.
   */
  int MPVLIB_CheckHn(int handleAddress);

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
    int handleAddress, int streamIndex, int streamObjectAddress, int streamCallbackAddress, int streamContextAddress
  );

  /**
   * Address: 0x00AE82A0 (FUN_00AE82A0, _MPV_SetPicUsrBuf)
   *
   * What it does:
   * Sets per-handle picture-user buffer/context and clears picture decode-state
   * latch.
   */
  std::int32_t* MPV_SetPicUsrBuf(int handleAddress, int userBufferAddress, int userContextAddress);

  /**
   * Address: 0x00AE82D0 (FUN_00AE82D0, _MPV_GetPicUsr)
   *
   * What it does:
   * Reads per-handle picture-user buffer/decode-state fields.
   */
  int* MPV_GetPicUsr(int handleAddress, int* outUserBufferAddress, int* outDecodeState);

  /**
   * Address: 0x00AE8300 (FUN_00AE8300, _MPV_DecodePicAtrSj)
   *
   * What it does:
   * Decodes picture attributes from an SJ stream using delimiter recovery
   * semantics.
   */
  int MPV_DecodePicAtrSj(int handleAddress, moho::movie::MPVSjStream* stream);

  /**
   * Address: 0x00AE84C0 (FUN_00AE84C0, _mpvhdec_GetCurDelim)
   *
   * What it does:
   * Reads current stream delimiter type from the active SJ chunk.
   */
  int mpvhdec_GetCurDelim(moho::movie::MPVSjStream* stream);

  /**
   * Address: 0x00AE8510 (FUN_00AE8510, _MPV_DecodePicAtr)
   *
   * What it does:
   * Decodes picture attributes from a raw buffer range through SJ memory
   * wrapper stream.
   */
  int MPV_DecodePicAtr(int handleAddress, const int* pictureDataRange, int* outConsumedBytes);

  /**
   * Address: 0x00AEAB20 (FUN_00AEAB20, _MPV_DecodeFrmSj)
   *
   * What it does:
   * Decodes one frame from an SJ stream, refreshes exported picture attributes,
   * and reports recovery-counter deltas.
   */
  int MPV_DecodeFrmSj(int handleAddress, moho::movie::MPVSjStream* stream, moho::movie::MPVFrameDecodeSession* frameSession);

  /**
   * Address: 0x00AE8570 (FUN_00AE8570, _mpvhdec_GetCodec)
   *
   * What it does:
   * Classifies codec lane for current chunk and caches result in handle state.
   */
  int mpvhdec_GetCodec(int handleAddress, moho::movie::MPVSjChunk* chunk);

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
  int MPVHDEC_RecoverSj(int handleAddress, int expectedDelimiterMask, moho::movie::MPVSjStream* stream);

  /**
   * Address: 0x00AE9AB0 (FUN_00AE9AB0, _MPV_MoveChunk)
   *
   * What it does:
   * Moves one stream chunk between lanes and returns moved byte count.
   */
  int MPV_MoveChunk(moho::movie::MPVSjStream* stream, int lane, int byteCount);

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
   */
  int MPVVLC_Init(int vlcContextBase);

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
