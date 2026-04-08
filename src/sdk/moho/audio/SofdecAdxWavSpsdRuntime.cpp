#include "moho/audio/SofdecRuntime.h"

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <windows.h>

namespace
{
  struct AdxbExecRuntimeView
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
    std::int16_t* sourceWordStream = nullptr; // +0x48
    std::int32_t sourceWordLimit = 0; // +0x4C
    std::int32_t outputChannels = 0; // +0x50
    std::int32_t outputBlockBytes = 0; // +0x54
    std::int32_t outputBlockSamples = 0; // +0x58
    std::int16_t* outputWordStream0 = nullptr; // +0x5C
    std::int32_t outputWordLimit = 0; // +0x60
    std::int32_t outputSecondChannelOffset = 0; // +0x64
    std::int32_t callbackLane0 = 0; // +0x68
    std::int32_t callbackLane1 = 0; // +0x6C
    std::int32_t callbackLane2 = 0; // +0x70
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
  };

  struct AdxPacketDecodeHandleRuntimeView
  {
    std::int32_t objectState = 0; // +0x00
    std::int32_t slotIndex = 0; // +0x04
    std::int32_t decodeMode = 0; // +0x08
    std::int32_t runState = 0; // +0x0C
    std::int32_t decodedBlockCount = 0; // +0x10
    std::int32_t sourceChannels = 0; // +0x14
    char* sourceBytes = nullptr; // +0x18
    std::int32_t sourceBlockCount = 0; // +0x1C
    std::uint16_t* outputLeft = nullptr; // +0x20
    std::uint16_t* outputRight = nullptr; // +0x24
    std::int16_t leftHistory[2]{}; // +0x28
    std::int16_t rightHistory[2]{}; // +0x2C
    std::int16_t coefficient0 = 0; // +0x30
    std::int16_t coefficient1 = 0; // +0x32
    std::uint16_t keyState = 0; // +0x34
    std::int16_t keyMultiplier = 0; // +0x36
    std::int16_t keyAdder = 0; // +0x38
  };

  static_assert(
    offsetof(AdxbExecRuntimeView, runState) == 0x04, "AdxbExecRuntimeView::runState offset must be 0x04"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, adxPacketDecoder) == 0x08,
    "AdxbExecRuntimeView::adxPacketDecoder offset must be 0x08"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, sourceChannels) == 0x0E,
    "AdxbExecRuntimeView::sourceChannels offset must be 0x0E"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, sourceWordStream) == 0x48,
    "AdxbExecRuntimeView::sourceWordStream offset must be 0x48"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, entryGetWriteFunc) == 0x78,
    "AdxbExecRuntimeView::entryGetWriteFunc offset must be 0x78"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, entryAddWriteFunc) == 0x80,
    "AdxbExecRuntimeView::entryAddWriteFunc offset must be 0x80"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, producedSampleCount) == 0x90,
    "AdxbExecRuntimeView::producedSampleCount offset must be 0x90"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, producedByteCount) == 0x94,
    "AdxbExecRuntimeView::producedByteCount offset must be 0x94"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, format) == 0x98, "AdxbExecRuntimeView::format offset must be 0x98"
  );
  static_assert(
    offsetof(AdxbExecRuntimeView, outputSamplePacking) == 0x9C,
    "AdxbExecRuntimeView::outputSamplePacking offset must be 0x9C"
  );

  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, runState) == 0x0C,
    "AdxPacketDecodeHandleRuntimeView::runState offset must be 0x0C"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, decodedBlockCount) == 0x10,
    "AdxPacketDecodeHandleRuntimeView::decodedBlockCount offset must be 0x10"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, sourceChannels) == 0x14,
    "AdxPacketDecodeHandleRuntimeView::sourceChannels offset must be 0x14"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, sourceBytes) == 0x18,
    "AdxPacketDecodeHandleRuntimeView::sourceBytes offset must be 0x18"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, sourceBlockCount) == 0x1C,
    "AdxPacketDecodeHandleRuntimeView::sourceBlockCount offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, outputLeft) == 0x20,
    "AdxPacketDecodeHandleRuntimeView::outputLeft offset must be 0x20"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, outputRight) == 0x24,
    "AdxPacketDecodeHandleRuntimeView::outputRight offset must be 0x24"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, leftHistory) == 0x28,
    "AdxPacketDecodeHandleRuntimeView::leftHistory offset must be 0x28"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, rightHistory) == 0x2C,
    "AdxPacketDecodeHandleRuntimeView::rightHistory offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, coefficient0) == 0x30,
    "AdxPacketDecodeHandleRuntimeView::coefficient0 offset must be 0x30"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, coefficient1) == 0x32,
    "AdxPacketDecodeHandleRuntimeView::coefficient1 offset must be 0x32"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, keyState) == 0x34,
    "AdxPacketDecodeHandleRuntimeView::keyState offset must be 0x34"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, keyMultiplier) == 0x36,
    "AdxPacketDecodeHandleRuntimeView::keyMultiplier offset must be 0x36"
  );
  static_assert(
    offsetof(AdxPacketDecodeHandleRuntimeView, keyAdder) == 0x38,
    "AdxPacketDecodeHandleRuntimeView::keyAdder offset must be 0x38"
  );
  static_assert(sizeof(AdxPacketDecodeHandleRuntimeView) == 0x3C, "AdxPacketDecodeHandleRuntimeView size must be 0x3C");

  constexpr char kRiffTag[4] = {'R', 'I', 'F', 'F'};
  constexpr char kWaveTag[4] = {'W', 'A', 'V', 'E'};
  constexpr char kSpsdTag[4] = {'S', 'P', 'S', 'D'};
  constexpr char kFormatTag[4] = {'f', 'm', 't', ' '};
  constexpr char kDataTag[4] = {'d', 'a', 't', 'a'};
  constexpr char kAuTagSnd[4] = {'.', 's', 'n', 'd'};
  constexpr char kAuTagSd[4] = {'.', 's', 'd', '\0'};
  constexpr char kFormTag[4] = {'F', 'O', 'R', 'M'};
  constexpr char kAiffTag[4] = {'A', 'I', 'F', 'F'};
  constexpr char kAiffChunkSsnd[4] = {'S', 'S', 'N', 'D'};
  constexpr char kAiffChunkComm[4] = {'C', 'O', 'M', 'M'};
  constexpr char kHeapNullPointerMessage[] = "NULL pointer is specified.";
  constexpr char kHeapShortBufferMessage[] = "Buffer size is too short.";
  constexpr char kHeapIllegalSizeMessage[] = "Illegal allocation size.";
  constexpr char kHeapIllegalAddressMessage[] = "Illegal memory address.";
  constexpr char kHeapOutOfMemoryMessage[] = "Can not allocate memory area.";
  constexpr char kDebugNewline[] = "\n";

  struct HeapManagerBlockRuntimeView;

  struct HeapManagerRuntimeView
  {
    std::uint8_t* heapBase = nullptr; // +0x00
    std::uint32_t heapByteCount = 0; // +0x04
    std::uint32_t alignmentBytes = 0; // +0x08
    HeapManagerBlockRuntimeView* head = nullptr; // +0x0C
  };

  struct HeapManagerBlockRuntimeView
  {
    std::uint32_t startOffset = 0; // +0x00
    std::uint32_t spanBytes = 0; // +0x04
    HeapManagerBlockRuntimeView* prev = nullptr; // +0x08
    HeapManagerBlockRuntimeView* next = nullptr; // +0x0C
    std::uint32_t userPointer = 0; // +0x10
  };

  struct XefindFoundFileInfo
  {
    const char* path = nullptr; // +0x00
    std::uint32_t fileSizeHigh = 0; // +0x04
    std::uint32_t fileSizeLow = 0; // +0x08
  };

  using XefindVisitCallback = std::int32_t(__cdecl*)(const XefindFoundFileInfo* foundFile, void* callbackContext);

  struct M2aFrameScanRuntimeView
  {
    std::uint8_t mUnknown00[0x4]{};
    std::int32_t parserState = 0; // +0x04
    std::int32_t parserErrorCode = 0; // +0x08
    std::uint8_t mUnknown0C[0x18]{};
    std::uint8_t* inputBytes = nullptr; // +0x24
    std::int32_t inputByteCount = 0; // +0x28
    std::uint8_t mUnknown2C[0x8]{};
    std::int32_t scanCursor = 0; // +0x34
    std::int32_t hasSyncLane = 0; // +0x38
    std::uint8_t mUnknown3C[0x4]{};
    std::int32_t enforceFrameEdge = 0; // +0x40
    std::int32_t markerScanMode = 0; // +0x44
    std::uint8_t markerByte0 = 0; // +0x48
    std::uint8_t markerByte1 = 0; // +0x49
    std::uint8_t mUnknown4A[0xE]{};
    std::int32_t hasMarkerPair = 0; // +0x58
  };

  static_assert(offsetof(HeapManagerRuntimeView, heapBase) == 0x00, "HeapManagerRuntimeView::heapBase offset must be 0x00");
  static_assert(
    offsetof(HeapManagerRuntimeView, heapByteCount) == 0x04,
    "HeapManagerRuntimeView::heapByteCount offset must be 0x04"
  );
  static_assert(
    offsetof(HeapManagerRuntimeView, alignmentBytes) == 0x08,
    "HeapManagerRuntimeView::alignmentBytes offset must be 0x08"
  );
  static_assert(offsetof(HeapManagerRuntimeView, head) == 0x0C, "HeapManagerRuntimeView::head offset must be 0x0C");
  static_assert(sizeof(HeapManagerRuntimeView) == 0x10, "HeapManagerRuntimeView size must be 0x10");

  static_assert(
    offsetof(HeapManagerBlockRuntimeView, startOffset) == 0x00,
    "HeapManagerBlockRuntimeView::startOffset offset must be 0x00"
  );
  static_assert(
    offsetof(HeapManagerBlockRuntimeView, spanBytes) == 0x04,
    "HeapManagerBlockRuntimeView::spanBytes offset must be 0x04"
  );
  static_assert(offsetof(HeapManagerBlockRuntimeView, prev) == 0x08, "HeapManagerBlockRuntimeView::prev offset must be 0x08");
  static_assert(offsetof(HeapManagerBlockRuntimeView, next) == 0x0C, "HeapManagerBlockRuntimeView::next offset must be 0x0C");
  static_assert(
    offsetof(HeapManagerBlockRuntimeView, userPointer) == 0x10,
    "HeapManagerBlockRuntimeView::userPointer offset must be 0x10"
  );
  static_assert(sizeof(HeapManagerBlockRuntimeView) == 0x14, "HeapManagerBlockRuntimeView size must be 0x14");

  static_assert(offsetof(M2aFrameScanRuntimeView, parserState) == 0x04, "M2aFrameScanRuntimeView::parserState offset must be 0x04");
  static_assert(
    offsetof(M2aFrameScanRuntimeView, parserErrorCode) == 0x08,
    "M2aFrameScanRuntimeView::parserErrorCode offset must be 0x08"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, inputBytes) == 0x24,
    "M2aFrameScanRuntimeView::inputBytes offset must be 0x24"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, inputByteCount) == 0x28,
    "M2aFrameScanRuntimeView::inputByteCount offset must be 0x28"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, scanCursor) == 0x34,
    "M2aFrameScanRuntimeView::scanCursor offset must be 0x34"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, hasSyncLane) == 0x38,
    "M2aFrameScanRuntimeView::hasSyncLane offset must be 0x38"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, enforceFrameEdge) == 0x40,
    "M2aFrameScanRuntimeView::enforceFrameEdge offset must be 0x40"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, markerScanMode) == 0x44,
    "M2aFrameScanRuntimeView::markerScanMode offset must be 0x44"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, markerByte0) == 0x48,
    "M2aFrameScanRuntimeView::markerByte0 offset must be 0x48"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, markerByte1) == 0x49,
    "M2aFrameScanRuntimeView::markerByte1 offset must be 0x49"
  );
  static_assert(
    offsetof(M2aFrameScanRuntimeView, hasMarkerPair) == 0x58,
    "M2aFrameScanRuntimeView::hasMarkerPair offset must be 0x58"
  );
  static_assert(sizeof(XefindFoundFileInfo) == 0x0C, "XefindFoundFileInfo size must be 0x0C");

  [[nodiscard]] std::uint32_t ReadBe32(const std::uint8_t* bytes)
  {
    return (static_cast<std::uint32_t>(bytes[0]) << 24u) |
           (static_cast<std::uint32_t>(bytes[1]) << 16u) |
           (static_cast<std::uint32_t>(bytes[2]) << 8u) |
           static_cast<std::uint32_t>(bytes[3]);
  }

  [[nodiscard]] std::uint16_t ReadBe16(const std::uint8_t* bytes)
  {
    return static_cast<std::uint16_t>(
      (static_cast<std::uint16_t>(bytes[0]) << 8u) | static_cast<std::uint16_t>(bytes[1])
    );
  }

  [[nodiscard]] std::int16_t DecodeBigEndianS16(const std::uint8_t* bytes)
  {
    return static_cast<std::int16_t>(ReadBe16(bytes));
  }

  [[nodiscard]] std::int16_t SignExtend8ToS16(std::uint8_t sample)
  {
    return static_cast<std::int16_t>(static_cast<std::int16_t>(static_cast<std::int8_t>(sample)) << 8u);
  }

  [[nodiscard]] std::int16_t DecodeWaveUnsigned8ToS16(std::uint8_t sample)
  {
    return static_cast<std::int16_t>((static_cast<std::int32_t>(sample) - 128) << 8u);
  }

  [[nodiscard]] std::int16_t DecodeMuLawToS16(std::uint8_t sample)
  {
    const std::uint8_t normalized = static_cast<std::uint8_t>(~sample);
    const std::int32_t sign = normalized & 0x80;
    const std::int32_t exponent = (normalized >> 4) & 0x07;
    const std::int32_t mantissa = normalized & 0x0F;
    std::int32_t decoded = ((mantissa << 3) + 0x84) << exponent;
    decoded -= 0x84;
    if (sign != 0) {
      decoded = -decoded;
    }
    return static_cast<std::int16_t>(decoded);
  }

  [[nodiscard]] int ComputeWritableSampleCount(AdxbExecRuntimeView* state, int* outWriteStartSample)
  {
    state->entryGetWriteFunc(
      state->entryGetWriteContext,
      &state->callbackLane0,
      &state->callbackLane1,
      &state->callbackLane2
    );

    int producedSamples = state->outputWordLimit - state->callbackLane0;
    if (producedSamples > state->callbackLane1) {
      producedSamples = state->callbackLane1;
    }
    if (producedSamples > state->sourceWordLimit) {
      producedSamples = state->sourceWordLimit;
    }

    *outWriteStartSample = state->callbackLane0;
    return producedSamples;
  }

  void CommitProducedSpan(AdxbExecRuntimeView* state, int producedSamples, int producedBytes)
  {
    state->producedSampleCount = producedSamples;
    state->producedByteCount = producedBytes;
    state->runState = 2;
  }

  [[nodiscard]] int FinishProducedSpan(AdxbExecRuntimeView* state)
  {
    int result = 0;
    if (state->runState == 2) {
      result = state->entryAddWriteFunc(
        state->entryAddWriteContext,
        state->producedByteCount,
        state->producedSampleCount
      );
      state->runState = 3;
    }
    return result;
  }

  [[nodiscard]] bool FourCcEquals(const std::uint8_t* bytes, const char tag[4])
  {
    return std::memcmp(bytes, tag, 4u) == 0;
  }

  [[nodiscard]] int ComputeBlockBytes(std::int32_t channels, std::int32_t bitsPerSample)
  {
    return (channels * bitsPerSample) / 8;
  }

  [[nodiscard]] AdxPacketDecodeHandleRuntimeView* AsPacketDecodeHandle(void* adxPacketDecoder)
  {
    return reinterpret_cast<AdxPacketDecodeHandleRuntimeView*>(adxPacketDecoder);
  }

  [[nodiscard]] std::int32_t ADXPD_EntryCommon(
    AdxPacketDecodeHandleRuntimeView* handle,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight,
    std::int32_t sourceChannels
  )
  {
    if (handle->runState != 0) {
      return 0;
    }

    handle->sourceBytes = sourceBytes;
    handle->sourceBlockCount = sourceBlockCount;
    handle->sourceChannels = sourceChannels;
    handle->outputLeft = outputLeft;
    handle->outputRight = outputRight;
    return 1;
  }

  [[nodiscard]] std::uint32_t AlignUpValue(std::uint32_t value, std::uint32_t alignment)
  {
    return alignment * ((value + alignment - 1u) / alignment);
  }

  [[nodiscard]] HeapManagerRuntimeView* AsHeapManager(void* heapManagerHandle)
  {
    return reinterpret_cast<HeapManagerRuntimeView*>(heapManagerHandle);
  }

  [[nodiscard]] HeapManagerBlockRuntimeView* BlockFromOffset(const HeapManagerRuntimeView* manager, std::uint32_t offset)
  {
    return reinterpret_cast<HeapManagerBlockRuntimeView*>(manager->heapBase + offset);
  }

  [[nodiscard]] std::uint32_t ComputeAlignedUserPointer(
    const HeapManagerRuntimeView* manager,
    const std::uint32_t startOffset
  )
  {
    const auto baseAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(manager->heapBase));
    const auto laneAddress = baseAddress + startOffset + manager->alignmentBytes + 31u;
    return AlignUpValue(laneAddress, manager->alignmentBytes);
  }

  void InitializeHeapBlock(
    const HeapManagerRuntimeView* manager,
    HeapManagerBlockRuntimeView* block,
    const std::uint32_t startOffset,
    const std::uint32_t spanBytes,
    HeapManagerBlockRuntimeView* prev,
    HeapManagerBlockRuntimeView* next
  )
  {
    block->startOffset = startOffset;
    block->spanBytes = spanBytes;
    block->prev = prev;
    block->next = next;
    block->userPointer = ComputeAlignedUserPointer(manager, startOffset);
  }

  [[nodiscard]] HeapManagerBlockRuntimeView* NextHeapBlock(HeapManagerBlockRuntimeView* block)
  {
    return block->next;
  }

  [[nodiscard]] std::int16_t ConvertFloatSampleToPcm16(float sample)
  {
    const double biased = (sample < 0.0f) ? (static_cast<double>(sample) - 0.5) : (static_cast<double>(sample) + 0.5);
    std::int32_t value = static_cast<std::int32_t>(biased);
    if (value > 0x7FFF) {
      value = 0x7FFF;
    } else if (value < -32768) {
      value = -32768;
    }
    return static_cast<std::int16_t>(value);
  }
} // namespace

extern "C"
{
  std::int32_t ADX_DecodeMono4(
    char* sourceBytes,
    std::int32_t blockCount,
    std::uint16_t* outSamples,
    std::int16_t* history,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  );
  std::int32_t ADX_DecodeSte4(
    char* sourceBytes,
    std::int32_t blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  );
  std::int32_t ADX_GetCoefficient(
    std::int32_t coefficientIndex,
    std::int32_t sampleRate,
    std::int16_t* outCoefficient0,
    std::int16_t* outCoefficient1
  );
  std::int32_t ADXPD_GetStat(void* adxPacketDecoder);
  std::uint8_t* AU_GetInfo(
    std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outSampleRate,
    std::int32_t* outChannels,
    std::int32_t* outSampleBits,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outPackingMode
  );
  std::uint8_t* AIFF_GetInfo(
    std::uint8_t* sourceBytes,
    std::uint32_t* outSampleRate,
    std::uint32_t* outChannels,
    std::uint32_t* outTotalSampleCount,
    std::int32_t* outSampleBits
  );
  std::int32_t adxpd_internal_error = 0;
  AdxPacketDecodeHandleRuntimeView adxpd_obj[32]{};
  std::int32_t xeci_thread_prio_2 = 0;
  XefindVisitCallback xeci_unk1_func = nullptr;
  void* xeci_unk1_func_obj = nullptr;
  LARGE_INTEGER xefind_last_scan_counter{};
  std::int32_t ADXB_ExecOneWav8(std::int32_t decoderAddress);
  std::int32_t ADXB_ExecOneWav16(std::int32_t decoderAddress);

  /**
   * Address: 0x00B29470 (_ADXB_CheckWav)
   *
   * What it does:
   * Validates RIFF/WAVE header tag lanes.
   */
  int ADXB_CheckWav(const std::uint8_t* headerBytes)
  {
    return std::memcmp(headerBytes, kRiffTag, sizeof(kRiffTag)) == 0 &&
           std::memcmp(headerBytes + 8, kWaveTag, sizeof(kWaveTag)) == 0;
  }

  /**
   * Address: 0x00B29790 (_ADXB_CheckSpsd)
   *
   * What it does:
   * Validates SPSD header tag lane.
   */
  int ADXB_CheckSpsd(const std::uint8_t* headerBytes)
  {
    return std::memcmp(headerBytes, kSpsdTag, sizeof(kSpsdTag)) == 0;
  }

  BOOL xeci_set_thread_prio_2();
  BOOL xeci_restore_thread_prio_2();
  std::int32_t __cdecl xefind_SearchSub(const char* rootPath, std::int32_t depth, std::uint32_t* counter);

  /**
   * Address: 0x00B27410 (_m2adec_convert_to_pcm16)
   *
   * What it does:
   * Converts one 1024-sample float window into clipped signed-16 PCM samples.
   */
  std::int32_t __cdecl m2adec_convert_to_pcm16(float* sourceSamples, std::int32_t destinationAddress)
  {
    auto* const destination = reinterpret_cast<std::int16_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(destinationAddress))
    );

    for (std::int32_t sampleIndex = 0; sampleIndex < 1024; ++sampleIndex) {
      destination[sampleIndex] = ConvertFloatSampleToPcm16(sourceSamples[sampleIndex]);
    }
    return 0;
  }

  /**
   * Address: 0x00B274D0 (sub_B274D0)
   *
   * What it does:
   * Scans one MPEG audio payload lane and reports next frame-sync offset.
   */
  std::int32_t __cdecl m2adec_scan_frame_sync(M2aFrameScanRuntimeView* state, std::int32_t* outOffset)
  {
    if (state->markerScanMode == 1) {
      if (state->hasSyncLane != 0 && state->hasMarkerPair != 0) {
        const std::int32_t inputByteCount = state->inputByteCount;
        std::int32_t scanIndex = 1;
        for (; scanIndex < inputByteCount; ++scanIndex) {
          const std::uint8_t byteValue = state->inputBytes[scanIndex];
          if (byteValue == state->markerByte0 || byteValue == state->markerByte1) {
            break;
          }
        }
        *outOffset = scanIndex;
        return 0;
      }

      state->parserState = 3;
      state->parserErrorCode = 2;
      return -1;
    }

    std::int32_t scanIndex = 1;
    const std::int32_t scanLimit = state->inputByteCount - 1;
    if (scanLimit > 1) {
      const std::uint8_t* cursor = state->inputBytes + 2;
      do {
        if (cursor[-1] == 0xFFu && (*cursor == 0xF8u || *cursor == 0xF9u)) {
          break;
        }
        ++scanIndex;
        ++cursor;
      } while (scanIndex < scanLimit);
    }

    if (state->inputBytes[scanIndex] == 0xFFu) {
      *outOffset = scanIndex;
      return 0;
    }

    *outOffset = scanIndex + 1;
    return 0;
  }

  /**
   * Address: 0x00B27470 (sub_B27470)
   *
   * What it does:
   * Resets scan cursor and applies frame-end state transitions after sync scan.
   */
  std::int32_t __cdecl m2adec_find_sync_offset(M2aFrameScanRuntimeView* state, std::int32_t* outOffset)
  {
    state->scanCursor = 0;
    const std::int32_t result = m2adec_scan_frame_sync(state, outOffset);
    if (result < 0) {
      return result;
    }

    if (state->enforceFrameEdge == 1) {
      const std::int32_t inputByteCount = state->inputByteCount;
      if (state->markerScanMode == 1) {
        *outOffset = inputByteCount;
        state->parserState = 2;
        return 0;
      }
      if (*outOffset >= inputByteCount) {
        state->parserState = 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B275B0 (sub_B275B0)
   *
   * What it does:
   * Heap manager startup no-op lane.
   */
  std::int32_t HEAPMNG_Init()
  {
    return 0;
  }

  /**
   * Address: 0x00B275C0 (sub_B275C0)
   *
   * What it does:
   * Heap manager shutdown no-op lane.
   */
  std::int32_t HEAPMNG_Finish()
  {
    return 0;
  }

  /**
   * Address: 0x00B27AA0 (sub_B27AA0)
   *
   * What it does:
   * Writes one debug-line message for heap manager error paths.
   */
  std::int32_t __cdecl heapmng_debug_log(const char* message)
  {
    OutputDebugStringA(message);
    OutputDebugStringA(kDebugNewline);
    return 0;
  }

  /**
   * Address: 0x00B27AC0 (_heapmng_clear)
   *
   * What it does:
   * Zero-fills one heap manager memory region.
   */
  std::int32_t __cdecl heapmng_clear(void* destination, const std::uint32_t byteCount)
  {
    std::memset(destination, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B27AE0 (_heapmng_copy)
   *
   * What it does:
   * Copies one raw memory span for heap manager reallocation.
   */
  std::uint32_t __cdecl heapmng_copy(void* destination, const void* source, const std::uint32_t byteCount)
  {
    std::memcpy(destination, source, byteCount);
    return byteCount;
  }

  /**
   * Address: 0x00B275D0 (_HEAPMNG_Create)
   *
   * What it does:
   * Initializes one in-place heap manager arena header.
   */
  std::int32_t __cdecl HEAPMNG_Create(void* heapBuffer, const std::uint32_t heapByteCount, void** outHeapManager)
  {
    if (heapBuffer == nullptr || outHeapManager == nullptr) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }
    if (heapByteCount < 0x400u) {
      heapmng_debug_log(kHeapShortBufferMessage);
      return -1;
    }

    heapmng_clear(heapBuffer, heapByteCount);
    auto* const manager = AsHeapManager(heapBuffer);
    manager->heapBase = static_cast<std::uint8_t*>(heapBuffer);
    manager->heapByteCount = heapByteCount;
    manager->alignmentBytes = 4;
    manager->head = nullptr;
    *outHeapManager = heapBuffer;
    return 0;
  }

  /**
   * Address: 0x00B27640 (_HEAPMNG_Destroy)
   *
   * What it does:
   * Clears one heap manager arena memory range.
   */
  std::int32_t __cdecl HEAPMNG_Destroy(void* heapManagerHandle)
  {
    if (heapManagerHandle == nullptr) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }

    const auto* const manager = AsHeapManager(heapManagerHandle);
    heapmng_clear(manager->heapBase, manager->heapByteCount);
    return 0;
  }

  /**
   * Address: 0x00B276F0 (_heapmng_first_alloc)
   *
   * What it does:
   * Allocates first block in an empty heap manager arena.
   */
  std::int32_t __cdecl heapmng_first_alloc(
    HeapManagerRuntimeView* manager,
    const std::uint32_t byteCount,
    std::uint32_t* outPointer
  )
  {
    const std::uint32_t requestedSpan = byteCount + manager->alignmentBytes + 32u;
    if (requestedSpan > manager->heapByteCount - 32u) {
      heapmng_debug_log(kHeapOutOfMemoryMessage);
      return -1;
    }

    auto* const block = BlockFromOffset(manager, 32u);
    InitializeHeapBlock(manager, block, 32u, requestedSpan, nullptr, nullptr);
    manager->head = block;
    *outPointer = block->userPointer;
    return 0;
  }

  /**
   * Address: 0x00B27760 (_heapmng_second_alloc)
   *
   * What it does:
   * Allocates and links one additional block in a populated arena.
   */
  std::int32_t __cdecl heapmng_second_alloc(
    HeapManagerRuntimeView* manager,
    const std::uint32_t byteCount,
    std::uint32_t* outPointer
  )
  {
    *outPointer = 0;
    const std::uint32_t requestedSpan = byteCount + manager->alignmentBytes + 32u;
    auto* cursor = manager->head;

    if (cursor->startOffset - 32u > requestedSpan) {
      auto* const prefix = BlockFromOffset(manager, 32u);
      InitializeHeapBlock(manager, prefix, 32u, requestedSpan, nullptr, cursor);
      manager->head = prefix;
      cursor->prev = prefix;
      *outPointer = prefix->userPointer;
      return 0;
    }

    auto* next = NextHeapBlock(cursor);
    while (next != nullptr) {
      const std::uint32_t gap = next->startOffset - cursor->spanBytes - cursor->startOffset;
      if (requestedSpan < gap) {
        const std::uint32_t startOffset = cursor->startOffset + cursor->spanBytes;
        auto* const block = BlockFromOffset(manager, startOffset);
        InitializeHeapBlock(manager, block, startOffset, requestedSpan, cursor, next);
        cursor->next = block;
        next->prev = block;
        *outPointer = block->userPointer;
        return 0;
      }
      cursor = next;
      next = NextHeapBlock(cursor);
    }

    const std::uint32_t appendOffset = cursor->startOffset + cursor->spanBytes;
    if (appendOffset + requestedSpan >= manager->heapByteCount) {
      heapmng_debug_log(kHeapOutOfMemoryMessage);
      return -1;
    }

    auto* const appended = BlockFromOffset(manager, appendOffset);
    InitializeHeapBlock(manager, appended, appendOffset, requestedSpan, cursor, nullptr);
    cursor->next = appended;
    *outPointer = appended->userPointer;
    return 0;
  }

  /**
   * Address: 0x00B27670 (_HEAPMNG_Allocate)
   *
   * What it does:
   * Allocates one block in heap manager arena, using first/second allocation
   * lanes depending on list state.
   */
  std::int32_t __cdecl HEAPMNG_Allocate(int heapManagerHandle, const SIZE_T byteCount, int* outPointer)
  {
    if (heapManagerHandle == 0 || outPointer == nullptr) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }
    if (byteCount == 0u) {
      heapmng_debug_log(kHeapIllegalSizeMessage);
      return -1;
    }

    auto* const manager = AsHeapManager(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(heapManagerHandle)))
    );

    std::uint32_t rawPointer = 0;
    std::int32_t result = 0;
    if (manager->head == nullptr) {
      result = heapmng_first_alloc(manager, static_cast<std::uint32_t>(byteCount), &rawPointer);
    } else {
      result = heapmng_second_alloc(manager, static_cast<std::uint32_t>(byteCount), &rawPointer);
    }

    if (result >= 0) {
      *outPointer = static_cast<int>(rawPointer);
      return 0;
    }
    return result;
  }

  /**
   * Address: 0x00B279C0 (sub_B279C0)
   *
   * What it does:
   * Resolves one heap block node by user pointer value.
   */
  std::int32_t __cdecl heapmng_find_block_by_user_pointer(
    HeapManagerRuntimeView* manager,
    const std::uint32_t userPointer,
    HeapManagerBlockRuntimeView** outBlock
  )
  {
    auto* block = manager->head;
    while (block != nullptr) {
      if (block->userPointer == userPointer) {
        *outBlock = block;
        return 0;
      }
      block = block->next;
    }

    heapmng_debug_log(kHeapIllegalAddressMessage);
    return -1;
  }

  /**
   * Address: 0x00B27A00 (_HEAPMNG_Free)
   *
   * What it does:
   * Unlinks one allocated block from heap manager arena list.
   */
  std::int32_t __cdecl HEAPMNG_Free(int heapManagerHandle, int pointerValue)
  {
    if (heapManagerHandle == 0 || pointerValue == 0) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }

    auto* const manager = AsHeapManager(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(heapManagerHandle)))
    );
    auto* block = manager->head;
    while (block != nullptr && block->userPointer != static_cast<std::uint32_t>(pointerValue)) {
      block = block->next;
    }
    if (block == nullptr) {
      heapmng_debug_log(kHeapIllegalAddressMessage);
      return -1;
    }

    auto* const prev = block->prev;
    auto* const next = block->next;
    if (prev != nullptr) {
      prev->next = next;
    } else {
      manager->head = next;
    }
    if (next != nullptr) {
      next->prev = prev;
    }
    return 0;
  }

  /**
   * Address: 0x00B278B0 (_HEAPMNG_ReAllocate)
   *
   * What it does:
   * Resizes one allocated heap block, attempting in-place growth before
   * allocate-copy-free fallback.
   */
  std::int32_t __cdecl HEAPMNG_ReAllocate(
    void* heapManagerHandle,
    void* currentPointer,
    const std::uint32_t byteCount,
    std::uint32_t* outPointer
  )
  {
    if (heapManagerHandle == nullptr || currentPointer == nullptr || outPointer == nullptr) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }
    if (byteCount == 0u) {
      heapmng_debug_log(kHeapIllegalSizeMessage);
      return -1;
    }

    auto* const manager = AsHeapManager(heapManagerHandle);
    const auto currentPointerValue = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(currentPointer));
    *outPointer = 0;

    HeapManagerBlockRuntimeView* block = nullptr;
    std::int32_t result = heapmng_find_block_by_user_pointer(manager, currentPointerValue, &block);
    if (result < 0) {
      return result;
    }

    const std::uint32_t alignment = manager->alignmentBytes;
    const std::uint32_t requiredSpan = alignment + byteCount + 32u;
    if (currentPointerValue % alignment == 0u) {
      if (requiredSpan <= block->spanBytes) {
        block->spanBytes = requiredSpan;
        *outPointer = currentPointerValue;
        return 0;
      }

      auto* const next = block->next;
      if (next != nullptr && (next->startOffset - block->startOffset > requiredSpan)) {
        block->spanBytes = requiredSpan;
        *outPointer = currentPointerValue;
        return 0;
      }
    }

    int newPointer = 0;
    result = HEAPMNG_Allocate(
      static_cast<int>(reinterpret_cast<std::uintptr_t>(heapManagerHandle)),
      static_cast<SIZE_T>(byteCount),
      &newPointer
    );
    if (result >= 0) {
      heapmng_copy(reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(newPointer))), currentPointer, byteCount);
      result = HEAPMNG_Free(
        static_cast<int>(reinterpret_cast<std::uintptr_t>(heapManagerHandle)),
        static_cast<int>(currentPointerValue)
      );
      if (result >= 0) {
        *outPointer = static_cast<std::uint32_t>(newPointer);
        return 0;
      }
    } else {
      *outPointer = currentPointerValue;
    }

    return result;
  }

  /**
   * Address: 0x00B27B00 (xeci_set_unk1)
   *
   * What it does:
   * Sets xefind callback and callback-context lanes.
   */
  std::int32_t __cdecl xeci_set_unk1(XefindVisitCallback callback, void* callbackContext)
  {
    xeci_unk1_func = callback;
    xeci_unk1_func_obj = callbackContext;
    return 0;
  }

  /**
   * Address: 0x00B27BA0 (_xefind_SearchSub)
   *
   * What it does:
   * Recursively enumerates files/directories and emits file hits through xefind
   * callback lane.
   */
  std::int32_t __cdecl xefind_SearchSub(const char* rootPath, const std::int32_t depth, std::uint32_t* counter)
  {
    char filePattern[MAX_PATH]{};
    WIN32_FIND_DATAA findData{};
    char joinedPath[MAX_PATH]{};

    std::sprintf(filePattern, "%s\\*", rootPath);
    QueryPerformanceCounter(&xefind_last_scan_counter);

    xeci_set_thread_prio_2();
    const HANDLE findHandle = FindFirstFileA(filePattern, &findData);
    xeci_restore_thread_prio_2();
    if (findHandle == INVALID_HANDLE_VALUE) {
      return 0;
    }

    while (true) {
      if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        if (depth != 0 && findData.cFileName[0] != '.') {
          std::sprintf(joinedPath, "%s\\%s", rootPath, findData.cFileName);
          const std::int32_t result = xefind_SearchSub(joinedPath, depth - 1, counter);
          if (result < 0) {
            return result;
          }
        }
      } else {
        std::sprintf(joinedPath, "%s\\%s", rootPath, findData.cFileName);
        XefindFoundFileInfo foundFile{};
        foundFile.path = joinedPath;
        foundFile.fileSizeLow = findData.nFileSizeLow;
        foundFile.fileSizeHigh = findData.nFileSizeHigh;

        if (counter != nullptr) {
          ++(*counter);
        }
        if (xeci_unk1_func != nullptr) {
          const std::int32_t result = xeci_unk1_func(&foundFile, xeci_unk1_func_obj);
          if (result < 0) {
            return result;
          }
        }
      }

      xeci_set_thread_prio_2();
      const BOOL hasNext = FindNextFileA(findHandle, &findData);
      xeci_restore_thread_prio_2();
      if (!hasNext) {
        break;
      }
    }

    xeci_set_thread_prio_2();
    FindClose(findHandle);
    xeci_restore_thread_prio_2();
    return 0;
  }

  /**
   * Address: 0x00B27B20 (sub_B27B20)
   *
   * What it does:
   * Normalizes one root path and starts recursive xefind search.
   */
  std::int32_t __cdecl xefind_Search(char* rootPath, const std::int32_t depth, std::uint32_t* counter)
  {
    if (counter != nullptr) {
      *counter = 0;
    }
    if (rootPath == nullptr) {
      return -1;
    }

    char normalizedPath[MAX_PATH]{};
    const char* readCursor = rootPath;
    char* writeCursor = normalizedPath;
    char copiedByte = 0;
    do {
      copiedByte = *readCursor;
      *writeCursor = copiedByte;
      ++readCursor;
      ++writeCursor;
    } while (copiedByte != 0);

    const std::size_t pathLength = std::strlen(normalizedPath);
    if (pathLength > 0 && normalizedPath[pathLength - 1] == '\\') {
      normalizedPath[pathLength - 1] = '\0';
    }

    return xefind_SearchSub(normalizedPath, depth, counter);
  }

  /**
   * Address: 0x00B27D00 (xeci_set_thread_prio_2)
   *
   * What it does:
   * Saves current thread priority then elevates to priority `2`.
   */
  BOOL xeci_set_thread_prio_2()
  {
    const HANDLE currentThread = GetCurrentThread();
    xeci_thread_prio_2 = GetThreadPriority(currentThread);
    return SetThreadPriority(currentThread, 2);
  }

  /**
   * Address: 0x00B27D20 (xeci_restore_thread_prio_2)
   *
   * What it does:
   * Restores current thread priority from the xefind temporary priority lane.
   */
  BOOL xeci_restore_thread_prio_2()
  {
    return SetThreadPriority(GetCurrentThread(), xeci_thread_prio_2);
  }

  /**
   * Address: 0x00B27D40 (_ADXPD_Init)
   *
   * What it does:
   * Clears the global ADX packet-decoder handle pool.
   */
  void ADXPD_Init()
  {
    std::memset(adxpd_obj, 0, sizeof(adxpd_obj));
  }

  /**
   * Address: 0x00B27D60 (_ADXPD_Finish)
   *
   * What it does:
   * Clears the global ADX packet-decoder handle pool.
   */
  void ADXPD_Finish()
  {
    std::memset(adxpd_obj, 0, sizeof(adxpd_obj));
  }

  /**
   * Address: 0x00B27D80 (_ADXPD_Create)
   *
   * What it does:
   * Allocates and initializes one handle from the fixed ADX packet-decoder
   * pool.
   */
  void* ADXPD_Create()
  {
    for (std::int32_t slotIndex = 0; slotIndex < 32; ++slotIndex) {
      auto* const handle = &adxpd_obj[slotIndex];
      if (handle->objectState == 0) {
        std::memset(handle, 0, sizeof(AdxPacketDecodeHandleRuntimeView));
        handle->slotIndex = slotIndex;
        handle->objectState = 1;
        handle->decodeMode = 0;
        handle->runState = 0;
        ADX_GetCoefficient(500, 44100, &handle->coefficient0, &handle->coefficient1);
        handle->leftHistory[0] = 0;
        handle->leftHistory[1] = 0;
        handle->rightHistory[0] = 0;
        handle->rightHistory[1] = 0;
        return handle;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B27E00 (_ADXPD_SetCoef)
   *
   * What it does:
   * Selects coefficient pair for one ADX packet-decoder handle.
   */
  std::int32_t ADXPD_SetCoef(void* adxPacketDecoder, std::int32_t sampleRate, std::int16_t coefficientIndex)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return ADX_GetCoefficient(coefficientIndex, sampleRate, &handle->coefficient0, &handle->coefficient1);
  }

  /**
   * Address: 0x00B27E20 (_ADXPD_SetDly)
   *
   * What it does:
   * Writes delay/history lanes for one ADX packet-decoder handle.
   */
  void* ADXPD_SetDly(void* adxPacketDecoder, const std::int16_t* delay0, const std::int16_t* delay1)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    handle->leftHistory[0] = delay0[0];
    handle->rightHistory[0] = delay1[0];
    handle->leftHistory[1] = delay0[1];
    handle->rightHistory[1] = delay1[1];
    return adxPacketDecoder;
  }

  /**
   * Address: 0x00B27E50 (_ADXPD_GetDly)
   *
   * What it does:
   * Reads delay/history lanes from one ADX packet-decoder handle.
   */
  void ADXPD_GetDly(void* adxPacketDecoder, std::int16_t* outDelay0, std::int16_t* outDelay1)
  {
    const auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    outDelay0[0] = handle->leftHistory[0];
    outDelay1[0] = handle->rightHistory[0];
    outDelay0[1] = handle->leftHistory[1];
    outDelay1[1] = handle->rightHistory[1];
  }

  /**
   * Address: 0x00B27E80 (_ADXPD_SetExtPrm)
   *
   * What it does:
   * Writes ADX key-extension parameters for one packet-decoder handle.
   */
  void* ADXPD_SetExtPrm(
    void* adxPacketDecoder,
    std::int16_t key0,
    std::int16_t keyMultiplier,
    std::int16_t keyAdder
  )
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    handle->keyState = static_cast<std::uint16_t>(key0);
    handle->keyMultiplier = keyMultiplier;
    handle->keyAdder = keyAdder;
    return adxPacketDecoder;
  }

  /**
   * Address: 0x00B27EA0 (_ADXPD_GetExtPrm)
   *
   * What it does:
   * Reads ADX key-extension parameters from one packet-decoder handle.
   */
  std::int16_t ADXPD_GetExtPrm(
    void* adxPacketDecoder,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    const auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    *outKey0 = static_cast<std::int16_t>(handle->keyState);
    *outKeyMultiplier = handle->keyMultiplier;
    *outKeyAdder = handle->keyAdder;
    return handle->keyAdder;
  }

  /**
   * Address: 0x00B27ED0 (_ADXPD_Destroy)
   *
   * What it does:
   * Releases one ADX packet-decoder handle slot in the global pool.
   */
  void ADXPD_Destroy(void* adxPacketDecoder)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    if (handle == nullptr) {
      return;
    }

    handle->objectState = 0;
    std::memset(handle, 0, sizeof(AdxPacketDecodeHandleRuntimeView));
  }

  /**
   * Address: 0x00B27EF0 (_ADXPD_SetMode)
   *
   * What it does:
   * Sets one packet-decoder mode lane.
   */
  std::int32_t ADXPD_SetMode(void* adxPacketDecoder, std::int32_t decodeMode)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    handle->decodeMode = decodeMode;
    return decodeMode;
  }

  /**
   * Address: 0x00B27F00 (_ADXPD_GetStat)
   *
   * What it does:
   * Returns one packet-decoder run-state lane.
   */
  std::int32_t ADXPD_GetStat(void* adxPacketDecoder)
  {
    const auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return handle->runState;
  }

  /**
   * Address: 0x00B27F10 (_ADXPD_EntryMono)
   *
   * What it does:
   * Enqueues one mono ADX packet-decode job into the handle.
   */
  std::int32_t __cdecl ADXPD_EntryMono(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return ADXPD_EntryCommon(handle, sourceBytes, sourceBlockCount, outputLeft, outputRight, 1);
  }

  /**
   * Address: 0x00B27F50 (_ADXPD_EntryPl2)
   *
   * What it does:
   * Enqueues one PL2/stereo ADX packet-decode job into the handle.
   */
  std::int32_t __cdecl ADXPD_EntryPl2(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return ADXPD_EntryCommon(handle, sourceBytes, sourceBlockCount, outputLeft, outputRight, 2);
  }

  /**
   * Address: 0x00B27F90 (_ADXPD_EntrySte)
   *
   * What it does:
   * Enqueues one standard stereo ADX packet-decode job into the handle.
   */
  std::int32_t __cdecl ADXPD_EntrySte(
    void* adxPacketDecoder,
    char* sourceBytes,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return ADXPD_EntryCommon(handle, sourceBytes, sourceBlockCount, outputLeft, outputRight, 1);
  }

  /**
   * Address: 0x00B27FD0 (_ADXPD_Start)
   *
   * What it does:
   * Transitions one packet-decoder handle from idle to queued state.
   */
  void* ADXPD_Start(void* adxPacketDecoder)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    if (handle->runState == 0) {
      handle->decodedBlockCount = 0;
      handle->runState = 1;
    }
    return adxPacketDecoder;
  }

  /**
   * Address: 0x00B27FF0 (_ADXPD_Stop)
   *
   * What it does:
   * Stops one packet-decoder handle and clears delay/history lanes.
   */
  void* ADXPD_Stop(void* adxPacketDecoder)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    handle->runState = 0;
    handle->leftHistory[0] = 0;
    handle->leftHistory[1] = 0;
    handle->rightHistory[0] = 0;
    handle->rightHistory[1] = 0;
    return handle->leftHistory;
  }

  /**
   * Address: 0x00B28010 (_ADXPD_Reset)
   *
   * What it does:
   * Clears completed state on one packet-decoder handle.
   */
  void* ADXPD_Reset(void* adxPacketDecoder)
  {
    auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    if (handle->runState == 3) {
      handle->runState = 0;
    }
    return adxPacketDecoder;
  }

  /**
   * Address: 0x00B28030 (_ADXPD_GetNumBlk)
   *
   * What it does:
   * Returns decoded-block count/status lane for one packet-decoder handle.
   */
  std::int32_t ADXPD_GetNumBlk(void* adxPacketDecoder)
  {
    const auto* const handle = AsPacketDecodeHandle(adxPacketDecoder);
    return handle->decodedBlockCount;
  }

  /**
   * Address: 0x00B28040 (_adxpd_error)
   *
   * What it does:
   * Marks the process-global ADX packet-decoder internal-error latch.
   */
  void adxpd_error()
  {
    adxpd_internal_error = 1;
  }

  /**
   * Address: 0x00B28050 (_ADXPD_ExecHndl)
   *
   * What it does:
   * Runs one ADX packet-decoder handle execution step and dispatches mono or
   * stereo decode path based on channel count.
   */
  void __cdecl ADXPD_ExecHndl(std::int32_t handleAddress)
  {
    auto* const handle = reinterpret_cast<AdxPacketDecodeHandleRuntimeView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handleAddress))
    );

    if (handle->runState == 1) {
      handle->runState = 2;
    }

    if (handle->runState != 2) {
      return;
    }

    if (handle->sourceChannels == 1) {
      handle->decodedBlockCount = ADX_DecodeMono4(
        handle->sourceBytes,
        handle->sourceBlockCount,
        handle->outputLeft,
        handle->leftHistory,
        handle->coefficient0,
        handle->coefficient1,
        &handle->keyState,
        handle->keyMultiplier,
        handle->keyAdder
      );
      handle->runState = 3;
      return;
    }

    handle->decodedBlockCount = ADX_DecodeSte4(
      handle->sourceBytes,
      handle->sourceBlockCount,
      handle->outputLeft,
      handle->leftHistory,
      handle->outputRight,
      handle->rightHistory,
      handle->coefficient0,
      handle->coefficient1,
      &handle->keyState,
      handle->keyMultiplier,
      handle->keyAdder
    );

    if ((handle->decodedBlockCount & 1) != 0) {
      adxpd_error();
    }

    handle->runState = 3;
  }

  /**
   * Address: 0x00B28130 (_ADXB_CheckAu)
   *
   * What it does:
   * Validates AU header magic (`.snd` and short-form `.sd`).
   */
  int ADXB_CheckAu(const std::uint8_t* headerBytes)
  {
    return std::memcmp(headerBytes, kAuTagSnd, sizeof(kAuTagSnd)) == 0 ||
           std::memcmp(headerBytes, kAuTagSd, sizeof(kAuTagSd)) == 0;
  }

  /**
   * Address: 0x00B28160 (_ADX_DecodeInfoAu)
   *
   * What it does:
   * Decodes AU header metadata and output packing class for ADXB state setup.
   */
  int __cdecl ADX_DecodeInfoAu(
    std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderIdentity,
    std::int8_t* outHeaderType,
    std::int8_t* outSourceSampleBits,
    std::int8_t* outSourceChannels,
    std::int8_t* outSourceBlockBytes,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outCodecClass,
    std::int32_t* outPackingMode
  )
  {
    if (headerSize < 8) {
      *outHeaderIdentity = 0;
      return -1;
    }

    const auto* const base = headerBytes;
    std::int32_t parsedSampleRate = headerSize;
    std::int32_t parsedChannels = 0;
    std::int32_t parsedSampleBits = 0;
    std::int32_t parsedTotalSampleCount = 0;
    std::int32_t parsedPackingMode = *outPackingMode;

    auto* streamData = AU_GetInfo(
      headerBytes,
      headerSize,
      &parsedSampleRate,
      &parsedChannels,
      &parsedSampleBits,
      &parsedTotalSampleCount,
      &parsedPackingMode
    );
    if (streamData == nullptr) {
      return -1;
    }

    const auto headerIdentity =
      static_cast<std::int16_t>(static_cast<std::uintptr_t>(streamData - base));
    *outHeaderIdentity = headerIdentity;
    if (headerIdentity <= 0) {
      return -1;
    }

    *outSampleRate = parsedSampleRate;
    *outSourceChannels = static_cast<std::int8_t>(parsedChannels);
    *outSourceSampleBits = static_cast<std::int8_t>(parsedSampleBits);
    *outTotalSampleCount = parsedTotalSampleCount;
    *outHeaderType = -1;
    *outSourceBlockBytes =
      static_cast<std::int8_t>(ComputeBlockBytes(parsedChannels, parsedSampleBits));
    *outCodecClass = 1;
    *outPackingMode = parsedPackingMode;
    return 0;
  }

  /**
   * Address: 0x00B28220 (_AU_GetInfo)
   *
   * What it does:
   * Parses AU container header lanes and returns stream-data start pointer.
   */
  std::uint8_t* AU_GetInfo(
    std::uint8_t* sourceBytes,
    std::int32_t sourceLength,
    std::int32_t* outSampleRate,
    std::int32_t* outChannels,
    std::int32_t* outSampleBits,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outPackingMode
  )
  {
    if (!ADXB_CheckAu(sourceBytes)) {
      return nullptr;
    }

    const auto dataOffset = static_cast<std::int32_t>(ReadBe32(sourceBytes + 4));
    if (dataOffset > sourceLength) {
      return nullptr;
    }

    const auto dataBytes = static_cast<std::int32_t>(ReadBe32(sourceBytes + 8));
    const auto encoding = ReadBe32(sourceBytes + 12);
    switch (encoding) {
      case 1u:
        *outPackingMode = 2;
        *outSampleBits = 8;
        break;
      case 2u:
        *outPackingMode = 1;
        *outSampleBits = 8;
        break;
      case 3u:
        *outPackingMode = 0;
        *outSampleBits = 16;
        break;
      default:
        return nullptr;
    }

    *outSampleRate = static_cast<std::int32_t>(ReadBe32(sourceBytes + 16));
    *outChannels = static_cast<std::int32_t>(ReadBe32(sourceBytes + 20));
    if (*outChannels == 0) {
      return nullptr;
    }

    if (*outPackingMode == 2 || *outPackingMode == 1) {
      *outTotalSampleCount = dataBytes / *outChannels;
    } else if (*outPackingMode == 0) {
      *outTotalSampleCount = dataBytes / 2 / *outChannels;
    } else {
      *outTotalSampleCount = 0x7FFF0000;
    }

    return sourceBytes + dataOffset;
  }

  /**
   * Address: 0x00B28480 (_ADXB_DecodeHeaderAu)
   *
   * What it does:
   * Decodes AU header fields into ADXB runtime state lanes.
   */
  int ADXB_DecodeHeaderAu(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize)
  {
    auto* const state = reinterpret_cast<AdxbExecRuntimeView*>(decoder);
    std::int16_t headerIdentity = 0;
    std::int32_t packingMode = 0;

    state->initState = 1;
    if (ADX_DecodeInfoAu(
          const_cast<std::uint8_t*>(headerBytes),
          headerSize,
          &headerIdentity,
          &state->headerType,
          &state->sourceSampleBits,
          &state->sourceChannels,
          &state->sourceBlockBytes,
          &state->sampleRate,
          &state->totalSampleCount,
          &state->sourceBlockSamples,
          &packingMode
        ) < 0) {
      return 0;
    }

    state->outputChannels = state->sourceChannels;
    state->outputBlockBytes = state->sourceBlockBytes;
    state->outputBlockSamples = state->sourceBlockSamples;
    state->outputWordStream0 = state->pcmBuffer0;
    state->outputWordLimit = state->pcmBufferSampleLimit;
    state->adpcmCoefficientIndex = 0;
    state->loopCount = 0;
    state->loopType = 0;
    state->loopEndOffset = 0;
    state->loopEndSample = 0;
    state->loopStartOffset = 0;
    state->loopStartSample = 0;
    state->loopInsertedSamples = 0;
    state->outputSecondChannelOffset = state->pcmBufferSecondChannelOffset;
    state->producedSampleCount = 0;
    state->producedByteCount = 0;
    state->format = 4;
    state->outputSamplePacking = static_cast<std::int16_t>(packingMode);
    return headerIdentity;
  }

  /**
   * Address: 0x00B28540 (_ADXB_ExecOneAu16)
   *
   * What it does:
   * Executes one AU 16-bit decode/write lane with big-endian sample swap.
   */
  int __cdecl ADXB_ExecOneAu16(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        int writeStartSample = 0;
        int producedSamples = ComputeWritableSampleCount(state, &writeStartSample);

        auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(state->sourceWordStream);
        auto* const outputPrimary = state->outputWordStream0 + writeStartSample;
        if (state->sourceChannels == 2) {
          auto* const outputSecondary =
            state->outputWordStream0 + writeStartSample + state->outputSecondChannelOffset;
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeBigEndianS16(sourceBytes + (4 * sampleIndex));
            outputSecondary[sampleIndex] = DecodeBigEndianS16(sourceBytes + (4 * sampleIndex) + 2);
          }
        } else {
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeBigEndianS16(sourceBytes + (2 * sampleIndex));
          }
        }

        const int packedSamples = producedSamples * state->sourceChannels;
        CommitProducedSpan(state, producedSamples, 2 * packedSamples);
      }
    }

    result = FinishProducedSpan(state);
    return result;
  }

  /**
   * Address: 0x00B28660 (_ADXB_ExecOneAu8)
   *
   * What it does:
   * Executes one AU signed-8 decode/write lane into signed-16 output.
   */
  int __cdecl ADXB_ExecOneAu8(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        int writeStartSample = 0;
        int producedSamples = ComputeWritableSampleCount(state, &writeStartSample);

        const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(state->sourceWordStream);
        auto* const outputPrimary = state->outputWordStream0 + writeStartSample;
        if (state->sourceChannels == 2) {
          auto* const outputSecondary =
            state->outputWordStream0 + writeStartSample + state->outputSecondChannelOffset;
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = SignExtend8ToS16(sourceBytes[2 * sampleIndex]);
            outputSecondary[sampleIndex] = SignExtend8ToS16(sourceBytes[(2 * sampleIndex) + 1]);
          }
        } else {
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = SignExtend8ToS16(sourceBytes[sampleIndex]);
          }
        }

        CommitProducedSpan(state, producedSamples, producedSamples * state->sourceChannels);
      }
    }

    result = FinishProducedSpan(state);
    return result;
  }

  /**
   * Address: 0x00B28760 (_ADXB_ExecOneAuUlaw)
   *
   * What it does:
   * Executes one AU u-law decode/write lane into signed-16 output.
   */
  int __cdecl ADXB_ExecOneAuUlaw(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        int writeStartSample = 0;
        int producedSamples = ComputeWritableSampleCount(state, &writeStartSample);

        const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(state->sourceWordStream);
        auto* const outputPrimary = state->outputWordStream0 + writeStartSample;
        if (state->sourceChannels == 2) {
          auto* const outputSecondary =
            state->outputWordStream0 + writeStartSample + state->outputSecondChannelOffset;
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeMuLawToS16(sourceBytes[2 * sampleIndex]);
            outputSecondary[sampleIndex] = DecodeMuLawToS16(sourceBytes[(2 * sampleIndex) + 1]);
          }
        } else {
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeMuLawToS16(sourceBytes[sampleIndex]);
          }
        }

        CommitProducedSpan(state, producedSamples, producedSamples * state->sourceChannels);
      }
    }

    result = FinishProducedSpan(state);
    return result;
  }

  /**
   * Address: 0x00B28870 (_ADXB_ExecOneAu)
   *
   * What it does:
   * Dispatches AU decode lane by packed sample format.
   */
  int __cdecl ADXB_ExecOneAu(std::int32_t decoderAddress)
  {
    const auto* const state =
      reinterpret_cast<const AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));

    if (state->outputSamplePacking == 2) {
      return ADXB_ExecOneAuUlaw(decoderAddress);
    }
    if (state->outputSamplePacking == 1) {
      return ADXB_ExecOneAu8(decoderAddress);
    }
    return ADXB_ExecOneAu16(decoderAddress);
  }

  /**
   * Address: 0x00B288A0 (_ADXB_CheckAiff)
   *
   * What it does:
   * Validates AIFF container header lanes.
   */
  int ADXB_CheckAiff(const std::uint8_t* headerBytes)
  {
    return std::memcmp(headerBytes, kFormTag, sizeof(kFormTag)) == 0 &&
           std::memcmp(headerBytes + 8, kAiffTag, sizeof(kAiffTag)) == 0;
  }

  /**
   * Address: 0x00B288D0 (_ADX_DecodeInfoAiff)
   *
   * What it does:
   * Decodes AIFF metadata lanes and output block shape for ADXB setup.
   */
  int __cdecl ADX_DecodeInfoAiff(
    std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderIdentity,
    std::int8_t* outHeaderType,
    std::int8_t* outSourceSampleBits,
    std::int8_t* outSourceChannels,
    std::int8_t* outSourceBlockBytes,
    std::int32_t* outSampleRate,
    std::uint32_t* outTotalSampleCount,
    std::uint32_t* outCodecClass
  )
  {
    if (headerSize < 4096) {
      *outHeaderIdentity = 0;
      return -1;
    }

    auto* const base = headerBytes;
    std::uint32_t parsedSampleRate = static_cast<std::uint32_t>(headerSize);
    std::uint32_t parsedChannels = 0;
    std::uint32_t parsedTotalSampleCount = 0;
    std::int32_t parsedSampleBits = 0;
    auto* streamData =
      AIFF_GetInfo(headerBytes, &parsedSampleRate, &parsedChannels, &parsedTotalSampleCount, &parsedSampleBits);
    if (streamData == nullptr) {
      return -1;
    }

    const auto headerIdentity =
      static_cast<std::int16_t>(static_cast<std::uintptr_t>(streamData - base));
    *outHeaderIdentity = headerIdentity;
    if (headerIdentity <= 0) {
      return -1;
    }

    *outSampleRate = static_cast<std::int32_t>(parsedSampleRate);
    *outSourceChannels = static_cast<std::int8_t>(parsedChannels);
    *outSourceSampleBits = static_cast<std::int8_t>(parsedSampleBits);
    *outTotalSampleCount = parsedTotalSampleCount;
    *outHeaderType = -1;
    *outSourceBlockBytes =
      static_cast<std::int8_t>(ComputeBlockBytes(static_cast<std::int32_t>(parsedChannels), parsedSampleBits));
    *outCodecClass = 1;
    return 0;
  }

  /**
   * Address: 0x00B28990 (_AIFF_GetInfo)
   *
   * What it does:
   * Walks AIFF chunks (`COMM` and `SSND`) and returns stream-data pointer plus
   * decoded channels/sample-rate/sample-size/sample-count lanes.
   */
  std::uint8_t* AIFF_GetInfo(
    std::uint8_t* sourceBytes,
    std::uint32_t* outSampleRate,
    std::uint32_t* outChannels,
    std::uint32_t* outTotalSampleCount,
    std::int32_t* outSampleBits
  )
  {
    if (!ADXB_CheckAiff(sourceBytes)) {
      return nullptr;
    }

    const std::uint32_t formSize = ReadBe32(sourceBytes + 4);
    auto* const formBody = sourceBytes + 12;
    auto* const formEnd = formBody + static_cast<std::ptrdiff_t>(formSize - 4);

    std::uint8_t* streamData = nullptr;
    bool foundSsnd = false;
    bool foundComm = false;
    auto* cursor = formBody;

    while (cursor < formEnd) {
      if ((formEnd - cursor) < 8) {
        break;
      }

      const std::uint32_t chunkId = ReadBe32(cursor);
      const std::uint32_t chunkSize = ReadBe32(cursor + 4);
      cursor += 8;

      if (chunkId == ReadBe32(reinterpret_cast<const std::uint8_t*>(kAiffChunkSsnd))) {
        if (!foundSsnd) {
          foundSsnd = true;
          if ((formEnd - cursor) < 4) {
            return nullptr;
          }

          const std::uint32_t dataOffset = ReadBe32(cursor);
          cursor += 4;
          streamData = cursor + static_cast<std::ptrdiff_t>(dataOffset);
          if (foundComm) {
            return streamData;
          }
        }
      } else if (chunkId == ReadBe32(reinterpret_cast<const std::uint8_t*>(kAiffChunkComm))) {
        if (!foundComm) {
          if (chunkSize < 18u) {
            return nullptr;
          }

          *outChannels = ReadBe16(cursor);
          *outTotalSampleCount = ReadBe32(cursor + 2);
          *outSampleBits = static_cast<std::int32_t>(ReadBe16(cursor + 6));

          const std::uint8_t exponent = cursor[9];
          const std::uint16_t mantissaHigh = ReadBe16(cursor + 10);
          const auto shiftCount = static_cast<unsigned int>(static_cast<std::uint8_t>(14u - exponent)) & 0x1Fu;
          *outSampleRate = static_cast<std::uint32_t>(mantissaHigh >> shiftCount);

          cursor += 18;
          foundComm = true;
          if (foundSsnd) {
            return streamData;
          }
        }
      } else {
        cursor += static_cast<std::ptrdiff_t>((chunkSize + 1u) & ~1u);
      }
    }

    return streamData;
  }

  /**
   * Address: 0x00B28C30 (_ADXB_DecodeHeaderAiff)
   *
   * What it does:
   * Decodes AIFF header fields into ADXB runtime state lanes.
   */
  int ADXB_DecodeHeaderAiff(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    std::int32_t headerSize
  )
  {
    auto* const state = reinterpret_cast<AdxbExecRuntimeView*>(decoder);
    std::int16_t headerIdentity = 0;
    std::uint32_t codecClass = 0;

    state->initState = 1;
    if (ADX_DecodeInfoAiff(
          const_cast<std::uint8_t*>(headerBytes),
          headerSize,
          &headerIdentity,
          &state->headerType,
          &state->sourceSampleBits,
          &state->sourceChannels,
          &state->sourceBlockBytes,
          &state->sampleRate,
          reinterpret_cast<std::uint32_t*>(&state->totalSampleCount),
          &codecClass
        ) < 0) {
      return 0;
    }

    state->outputChannels = state->sourceChannels;
    state->outputBlockBytes = state->sourceBlockBytes;
    state->outputBlockSamples = state->sourceBlockSamples;
    state->outputWordStream0 = state->pcmBuffer0;
    state->outputWordLimit = state->pcmBufferSampleLimit;
    state->adpcmCoefficientIndex = 0;
    state->loopCount = 0;
    state->loopType = 0;
    state->loopEndOffset = 0;
    state->loopEndSample = 0;
    state->loopStartOffset = 0;
    state->loopStartSample = 0;
    state->loopInsertedSamples = 0;
    state->outputSecondChannelOffset = state->pcmBufferSecondChannelOffset;
    state->producedSampleCount = 0;
    state->producedByteCount = 0;
    state->format = 3;
    state->outputSamplePacking = (state->sourceSampleBits == 8) ? 1 : 0;
    return headerIdentity;
  }

  /**
   * Address: 0x00B28D00 (_ADXB_ExecOneAiff16)
   *
   * What it does:
   * Executes one AIFF 16-bit decode/write lane with big-endian sample swap.
   */
  int __cdecl ADXB_ExecOneAiff16(std::int32_t decoderAddress)
  {
    return ADXB_ExecOneAu16(decoderAddress);
  }

  /**
   * Address: 0x00B28E20 (_ADXB_ExecOneAiff8)
   *
   * What it does:
   * Executes one AIFF signed-8 decode/write lane into signed-16 output.
   */
  int __cdecl ADXB_ExecOneAiff8(std::int32_t decoderAddress)
  {
    return ADXB_ExecOneAu8(decoderAddress);
  }

  /**
   * Address: 0x00B28F20 (_ADXB_ExecOneAiff)
   *
   * What it does:
   * Dispatches AIFF decode lane by packed sample format.
   */
  int __cdecl ADXB_ExecOneAiff(std::int32_t decoderAddress)
  {
    const auto* const state =
      reinterpret_cast<const AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    if (state->outputSamplePacking == 1) {
      return ADXB_ExecOneAiff8(decoderAddress);
    }
    return ADXB_ExecOneAiff16(decoderAddress);
  }

  /**
   * Address: 0x00B28F40 (_ADX_DecodeInfoWav)
   *
   * What it does:
   * Decodes WAV format/data chunk metadata and output packing class.
   */
  int __cdecl ADX_DecodeInfoWav(
    const std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderIdentity,
    std::int8_t* outHeaderType,
    std::int8_t* outSourceSampleBits,
    std::int8_t* outSourceChannels,
    std::int8_t* outSourceBlockBytes,
    std::uint32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::uint32_t* outCodecClass,
    std::int16_t* outPackingMode
  )
  {
    int fmtOffset = -1;
    for (int offset = 0; offset < headerSize; ++offset) {
      if ((offset + 4) <= headerSize && FourCcEquals(headerBytes + offset, kFormatTag)) {
        fmtOffset = offset;
        break;
      }
    }
    if (fmtOffset < 0 || (fmtOffset % 4) != 0) {
      return -1;
    }

    const auto* const formatChunk = headerBytes + fmtOffset + 8;
    if (*reinterpret_cast<const std::uint16_t*>(formatChunk) > 1u) {
      return -1;
    }

    int dataOffset = -1;
    for (int offset = 0; offset < headerSize; ++offset) {
      if ((offset + 4) <= headerSize && FourCcEquals(headerBytes + offset, kDataTag)) {
        dataOffset = offset;
        break;
      }
    }
    if (dataOffset < 0) {
      return -1;
    }

    const auto dataBytes = *reinterpret_cast<const std::uint32_t*>(headerBytes + dataOffset + 4);
    *outHeaderIdentity = static_cast<std::int16_t>(dataOffset + 8);
    *outHeaderType = -1;
    *outSampleRate = *reinterpret_cast<const std::uint32_t*>(formatChunk + 4);
    *outSourceChannels = static_cast<std::int8_t>(formatChunk[2]);
    *outSourceSampleBits = static_cast<std::int8_t>(formatChunk[14]);
    *outSourceBlockBytes = static_cast<std::int8_t>(formatChunk[12]);
    *outTotalSampleCount = static_cast<std::int32_t>(dataBytes / static_cast<std::uint8_t>(*outSourceBlockBytes));
    *outCodecClass = 1;

    if (*outSourceSampleBits == 16) {
      *outPackingMode = 0;
    } else if (*outSourceSampleBits == 8) {
      *outPackingMode = 1;
    } else if (*outSourceSampleBits == 4) {
      *outSourceBlockBytes = static_cast<std::int8_t>(2 * *outSourceChannels);
      *outCodecClass = 4;
      *outTotalSampleCount =
        static_cast<std::int32_t>(dataBytes / 2 / static_cast<std::uint8_t>(*outSourceChannels));
      *outSourceSampleBits = 16;
      *outPackingMode = 2;
    }

    if (*outSourceSampleBits == 0 ||
        *outSourceBlockBytes == 0 ||
        *outSourceChannels <= 0 ||
        *outSourceChannels > 2) {
      return -1;
    }

    return (*outSampleRate != 0u) ? 0 : -1;
  }

  /**
   * Address: 0x00B29090 (_ADXB_DecodeHeaderWav)
   *
   * What it does:
   * Decodes WAV header fields into ADXB runtime state lanes.
   */
  int ADXB_DecodeHeaderWav(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    std::int32_t headerSize
  )
  {
    auto* const state = reinterpret_cast<AdxbExecRuntimeView*>(decoder);
    std::int16_t headerIdentity = 0;
    std::uint32_t codecClass = 0;

    state->initState = 1;
    if (ADX_DecodeInfoWav(
          headerBytes,
          headerSize,
          &headerIdentity,
          &state->headerType,
          &state->sourceSampleBits,
          &state->sourceChannels,
          &state->sourceBlockBytes,
          reinterpret_cast<std::uint32_t*>(&state->sampleRate),
          &state->totalSampleCount,
          &codecClass,
          &state->outputSamplePacking
        ) < 0) {
      return 0;
    }

    state->outputChannels = state->sourceChannels;
    state->outputBlockBytes = state->sourceBlockBytes;
    state->outputBlockSamples = state->sourceBlockSamples;
    state->outputWordStream0 = state->pcmBuffer0;
    state->outputWordLimit = state->pcmBufferSampleLimit;
    state->adpcmCoefficientIndex = 0;
    state->loopCount = 0;
    state->loopType = 0;
    state->loopEndOffset = 0;
    state->loopEndSample = 0;
    state->loopStartOffset = 0;
    state->loopStartSample = 0;
    state->loopInsertedSamples = 0;
    state->outputSecondChannelOffset = state->pcmBufferSecondChannelOffset;
    state->producedSampleCount = 0;
    state->producedByteCount = 0;
    state->format = 1;
    return headerIdentity;
  }

  /**
   * Address: 0x00B29150 (_ADXB_ExecOneWav16)
   *
   * What it does:
   * Executes one WAV 16-bit decode/write lane.
   */
  int __cdecl ADXB_ExecOneWav16(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        int writeStartSample = 0;
        const int producedSamples = ComputeWritableSampleCount(state, &writeStartSample);

        const auto* const sourceWords = reinterpret_cast<const std::int16_t*>(state->sourceWordStream);
        auto* const outputPrimary = state->outputWordStream0 + writeStartSample;
        if (state->sourceChannels == 2) {
          auto* const outputSecondary =
            state->outputWordStream0 + writeStartSample + state->outputSecondChannelOffset;
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = sourceWords[2 * sampleIndex];
            outputSecondary[sampleIndex] = sourceWords[(2 * sampleIndex) + 1];
          }
        } else {
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = sourceWords[sampleIndex];
          }
        }

        const int packedSamples = producedSamples * state->sourceChannels;
        CommitProducedSpan(state, producedSamples, 2 * packedSamples);
      }
    }

    result = FinishProducedSpan(state);
    return result;
  }

  /**
   * Address: 0x00B29250 (_ADXB_ExecOneWav8)
   *
   * What it does:
   * Executes one WAV unsigned-8 decode/write lane into signed-16 output.
   */
  int __cdecl ADXB_ExecOneWav8(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        int writeStartSample = 0;
        const int producedSamples = ComputeWritableSampleCount(state, &writeStartSample);

        const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(state->sourceWordStream);
        auto* const outputPrimary = state->outputWordStream0 + writeStartSample;
        if (state->sourceChannels == 2) {
          auto* const outputSecondary =
            state->outputWordStream0 + writeStartSample + state->outputSecondChannelOffset;
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeWaveUnsigned8ToS16(sourceBytes[2 * sampleIndex]);
            outputSecondary[sampleIndex] = DecodeWaveUnsigned8ToS16(sourceBytes[(2 * sampleIndex) + 1]);
          }
        } else {
          for (int sampleIndex = 0; sampleIndex < producedSamples; ++sampleIndex) {
            outputPrimary[sampleIndex] = DecodeWaveUnsigned8ToS16(sourceBytes[sampleIndex]);
          }
        }

        CommitProducedSpan(state, producedSamples, producedSamples * state->sourceChannels);
      }
    }

    result = FinishProducedSpan(state);
    return result;
  }

  /**
   * Address: 0x00B294E0 (_ADX_DecodeInfoSpsd)
   *
   * What it does:
   * Decodes SPSD header metadata lanes into ADXB runtime outputs.
   */
  int __cdecl ADX_DecodeInfoSpsd(
    const std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderIdentity,
    std::int8_t* outHeaderType,
    std::int8_t* outSourceSampleBits,
    std::int8_t* outSourceChannels,
    std::int8_t* outSourceBlockBytes,
    std::int32_t* outSourceBlockSamples,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int16_t* outFormat
  )
  {
    (void)headerSize;
    *outHeaderIdentity = static_cast<std::int16_t>(16 * headerBytes[7]);
    *outSourceChannels = static_cast<std::int8_t>((headerBytes[9] & 3) + 1);
    *outSampleRate = static_cast<std::int32_t>(
      static_cast<std::uint16_t>(headerBytes[42] | (headerBytes[43] << 8))
    );

    switch (headerBytes[8]) {
      case 0:
        *outSourceSampleBits = 16;
        *outSourceBlockBytes = static_cast<std::int8_t>(2 * (*outSourceChannels));
        *outSourceBlockSamples = 1;
        *outTotalSampleCount = static_cast<std::int32_t>(
          (static_cast<std::int32_t>(
             headerBytes[12] | (headerBytes[13] << 8) | (headerBytes[14] << 16) | (headerBytes[15] << 24)
           )) /
          2
        );
        *outFormat = 0;
        break;

      case 1:
        *outSourceSampleBits = 8;
        *outSourceBlockBytes = *outSourceChannels;
        *outSourceBlockSamples = 1;
        *outTotalSampleCount = static_cast<std::int32_t>(
          headerBytes[12] | (headerBytes[13] << 8) | (headerBytes[14] << 16) | (headerBytes[15] << 24)
        );
        *outFormat = 1;
        break;

      case 2:
      case 3:
        *outSourceSampleBits = 4;
        *outSourceBlockBytes = *outSourceChannels;
        *outSourceBlockSamples = 2;
        *outTotalSampleCount =
          2 *
          static_cast<std::int32_t>(
            headerBytes[12] | (headerBytes[13] << 8) | (headerBytes[14] << 16) | (headerBytes[15] << 24)
          );
        *outFormat = 2;
        break;

      default:
        break;
    }

    // Runtime always normalizes SPSD decode lane to 16-bit mono-step output.
    *outSourceBlockBytes = 2;
    *outSourceBlockSamples = 1;
    *outTotalSampleCount = static_cast<std::int32_t>(
      (static_cast<std::int32_t>(
         headerBytes[12] | (headerBytes[13] << 8) | (headerBytes[14] << 16) | (headerBytes[15] << 24)
       )) /
      2
    );
    *outSourceSampleBits = 16;
    *outHeaderType = -1;
    return 0;
  }

  /**
   * Address: 0x00B295D0 (_ADXB_DecodeHeaderSpsd)
   *
   * What it does:
   * Decodes SPSD header into ADXB runtime fields and resets decode-state lanes.
   */
  int ADXB_DecodeHeaderSpsd(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize)
  {
    auto* const state = reinterpret_cast<AdxbExecRuntimeView*>(decoder);
    std::int16_t headerIdentity = 0;

    state->initState = 1;
    if (ADX_DecodeInfoSpsd(
          headerBytes,
          headerSize,
          &headerIdentity,
          &state->headerType,
          &state->sourceSampleBits,
          &state->sourceChannels,
          &state->sourceBlockBytes,
          &state->sourceBlockSamples,
          &state->sampleRate,
          &state->totalSampleCount,
          &state->outputSamplePacking
        ) < 0) {
      return 0;
    }

    state->outputChannels = state->sourceChannels;
    state->outputBlockBytes = state->sourceBlockBytes;
    state->outputBlockSamples = state->sourceBlockSamples;
    state->outputWordStream0 = state->pcmBuffer0;
    state->outputWordLimit = state->pcmBufferSampleLimit;
    state->adpcmCoefficientIndex = 0;
    state->loopCount = 0;
    state->loopType = 0;
    state->loopEndOffset = 0;
    state->loopEndSample = 0;
    state->loopStartOffset = 0;
    state->loopStartSample = 0;
    state->loopInsertedSamples = 0;
    state->outputSecondChannelOffset = state->pcmBufferSecondChannelOffset;
    state->entryCommittedBytes = 0;
    state->entrySubmittedBytes = 0;
    state->format = 2;
    return headerIdentity;
  }

  /**
   * Address: 0x00B29360 (_ADXB_ExecOneWav4)
   *
   * What it does:
   * Executes one ADXB WAV-4 decode/write lane and commits produced bytes.
   */
  int __cdecl ADXB_ExecOneWav4(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    auto* sourceWords = state->sourceWordStream;
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        state->entryGetWriteFunc(
          state->entryGetWriteContext,
          &state->callbackLane0,
          &state->callbackLane1,
          &state->callbackLane2
        );

        int startSample = state->callbackLane0;
        int producedSamples = state->outputWordLimit - startSample;
        if (producedSamples > state->callbackLane1) {
          producedSamples = state->callbackLane1;
        }
        if (producedSamples > state->sourceWordLimit) {
          producedSamples = state->sourceWordLimit;
        }

        auto* outputBase = state->outputWordStream0 + startSample;
        if (state->sourceChannels == 2) {
          auto* outputSecond =
            state->outputWordStream0 + startSample + state->outputSecondChannelOffset;
          if (producedSamples > 0) {
            const std::uint8_t* sourceBytes =
              reinterpret_cast<const std::uint8_t*>(sourceWords) + 3;
            int remaining = producedSamples;
            do {
              const std::int16_t leftSample = static_cast<std::int16_t>(
                (static_cast<std::uint16_t>(sourceBytes[-1]) << 8) |
                static_cast<std::uint16_t>(sourceBytes[-3])
              );
              sourceBytes += 4;

              const std::int16_t rightSample = static_cast<std::int16_t>(
                (static_cast<std::uint16_t>(sourceBytes[-4]) << 8) |
                static_cast<std::uint16_t>(sourceBytes[-6])
              );

              *outputBase = leftSample;
              *outputSecond = rightSample;
              ++outputBase;
              ++outputSecond;
              --remaining;
            } while (remaining != 0);
          }
        } else if (producedSamples > 0) {
          auto* src = sourceWords;
          auto* dst = outputBase;
          int remaining = producedSamples;
          do {
            *dst++ = *src++;
            --remaining;
          } while (remaining != 0);
        }

        state->producedSampleCount = producedSamples;
        state->producedByteCount = 2 * producedSamples * state->sourceChannels;
        state->runState = 2;
      }
    }

    if (state->runState == 2) {
      result = state->entryAddWriteFunc(
        state->entryAddWriteContext,
        state->producedByteCount,
        state->producedSampleCount
      );
      state->runState = 3;
    }

    return result;
  }

  /**
   * Address: 0x00B294A0 (_ADXB_ExecOneWav)
   *
   * What it does:
   * Dispatches WAV decode lane by format class.
   */
  int __cdecl ADXB_ExecOneWav(std::int32_t decoderAddress)
  {
    const auto* const state =
      reinterpret_cast<const AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));

    switch (state->outputSamplePacking) {
      case 2:
        return ADXB_ExecOneWav4(decoderAddress);
      case 1:
        return ADXB_ExecOneWav8(decoderAddress);
      case 0:
        return ADXB_ExecOneWav16(decoderAddress);
      default:
        return state->outputSamplePacking;
    }
  }

  /**
   * Address: 0x00B29690 (_ADXB_ExecOneSpsd)
   *
   * What it does:
   * Executes one ADXB SPSD decode/write lane and commits produced bytes.
   */
  int __cdecl ADXB_ExecOneSpsd(std::int32_t decoderAddress)
  {
    auto* const state =
      reinterpret_cast<AdxbExecRuntimeView*>(static_cast<std::uintptr_t>(decoderAddress));
    auto* sourceWords = state->sourceWordStream;
    int result = state->runState;

    if (result == 1) {
      result = ADXPD_GetStat(state->adxPacketDecoder);
      if (result == 0) {
        state->entryGetWriteFunc(
          state->entryGetWriteContext,
          &state->callbackLane0,
          &state->callbackLane1,
          &state->callbackLane2
        );

        int startSample = state->callbackLane0;
        result = state->outputWordLimit - startSample;
        if (result > state->callbackLane1) {
          result = state->callbackLane1;
        }
        if (result > state->sourceWordLimit) {
          result = state->sourceWordLimit;
        }

        auto* outputBase = state->outputWordStream0 + startSample;
        if (state->sourceChannels == 2) {
          auto* outputSecond =
            state->outputWordStream0 + startSample + state->outputSecondChannelOffset;
          int sampleIndex = 0;
          if (result > 0) {
            do {
              const std::int16_t leftSample = sourceWords[2 * sampleIndex];
              const std::int16_t rightSample = sourceWords[(2 * sampleIndex) + 1];
              *outputBase++ = leftSample;
              *outputSecond++ = rightSample;
              ++sampleIndex;
            } while (sampleIndex < result);
          }
        } else if (result > 0) {
          auto* dst = outputBase;
          const auto* src = sourceWords;
          int remaining = result;
          do {
            *dst++ = *src++;
            --remaining;
          } while (remaining != 0);
        }

        state->producedSampleCount = result;
        state->producedByteCount = 2 * result * state->sourceChannels;
        state->runState = 2;
      }
    }

    if (state->runState == 2) {
      result = state->entryAddWriteFunc(
        state->entryAddWriteContext,
        state->producedByteCount,
        state->producedSampleCount
      );
      state->runState = 3;
    }

    return result;
  }
}
