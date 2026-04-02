#include "moho/movie/MPVDecoder.h"

#include <cstring>

namespace
{
  extern "C" {
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
  using moho::movie::MPVInterpolationKernelFn;
  using moho::movie::MPVPredictionVectorSet;
  using moho::movie::MPVPredictionKernelState;
  using moho::movie::MPVSjChunk;
  using moho::movie::MPVSjStream;
  using moho::movie::MPVSpatialDelta;

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

  MPVInterpolationKernelFn g_mpvInterpolationDispatch[8]{};
  bool g_mpvInterpolationDispatchInitialized = false;

  inline std::uint8_t* AddressToMutablePointer(const int address)
  {
    return reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(address)));
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

  inline MPVSjStreamView* AsSjStreamView(MPVSjStream* stream)
  {
    return reinterpret_cast<MPVSjStreamView*>(stream);
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
