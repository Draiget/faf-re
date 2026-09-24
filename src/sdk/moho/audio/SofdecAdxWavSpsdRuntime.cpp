#include "moho/audio/SofdecRuntime.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <windows.h>

namespace
{
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

  /** Bytes the arena header and every block header reserve ahead of their data. */
  constexpr std::uint32_t kHeapHeaderBytes = 0x20;

  /**
   * One allocation in a `HeapManager` arena. The header lives at the start of
   * the block's span; the caller's memory starts at the first aligned address
   * past the header, and the span reserves room for that alignment slack.
   */
  struct HeapManagerBlock
  {
    std::uint32_t startOffset = 0;    // +0x00  from the arena base
    std::uint32_t spanBytes = 0;      // +0x04  header + alignment slack + payload
    HeapManagerBlock* prev = nullptr; // +0x08  lower-addressed neighbour
    HeapManagerBlock* next = nullptr; // +0x0C  higher-addressed neighbour
    std::uint32_t userAddress = 0;    // +0x10  address handed to the caller
  };
  static_assert(offsetof(HeapManagerBlock, prev) == 0x08);
  static_assert(offsetof(HeapManagerBlock, userAddress) == 0x10);
  static_assert(sizeof(HeapManagerBlock) == 0x14);

  /**
   * CRI heap manager (`HEAPMNG`): an arena whose own header sits at the start
   * of the buffer it manages. Blocks are carved from the arena past that
   * header and kept in an address-ordered, null-terminated list.
   */
  struct HeapManager
  {
    std::uint8_t* arenaBase = nullptr;  // +0x00  the arena, which begins with this header
    std::uint32_t arenaBytes = 0;       // +0x04
    std::uint32_t alignment = 0;        // +0x08  4 unless changed
    HeapManagerBlock* head = nullptr;   // +0x0C  lowest-addressed block

    /** First `alignment` boundary past the header of a block at `startOffset`. */
    [[nodiscard]] std::uint32_t UserAddressAt(const std::uint32_t startOffset) const
    {
      const auto blockAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(arenaBase)) + startOffset;
      return (blockAddress + kHeapHeaderBytes + alignment - 1) / alignment * alignment;
    }

    /** Builds a block header at `startOffset` between `prev` and `next`. */
    HeapManagerBlock* PlaceBlock(
      const std::uint32_t startOffset,
      const std::uint32_t spanBytes,
      HeapManagerBlock* const prev,
      HeapManagerBlock* const next
    ) const
    {
      return ::new (arenaBase + startOffset) HeapManagerBlock{startOffset, spanBytes, prev, next, UserAddressAt(startOffset)};
    }

    /** Span a request of `byteCount` needs: header, alignment slack, payload. */
    [[nodiscard]] std::uint32_t SpanFor(const std::uint32_t byteCount) const
    {
      return byteCount + alignment + kHeapHeaderBytes;
    }
  };
  static_assert(offsetof(HeapManager, alignment) == 0x08);
  static_assert(offsetof(HeapManager, head) == 0x0C);
  static_assert(sizeof(HeapManager) == 0x10);

  /** Opaque `HEAPMNG` handle, as the M2A callers hold it, to the arena header. */
  [[nodiscard]] HeapManager* HeapManagerFromHandle(const int handle)
  {
    return reinterpret_cast<HeapManager*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle)));
  }

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

  /** RIFF chunk header: four-character id and little-endian body size. */
  struct RiffChunkHeader
  {
    char id[4];         // +0x00
    std::uint32_t size; // +0x04
  };
  static_assert(sizeof(RiffChunkHeader) == 0x08);

  /**
   * WAVE `fmt ` chunk body (PCMWAVEFORMAT). `formatTag` is signed because the
   * WAV parser rejects tags above 1 with a signed compare, which lets
   * WAVE_FORMAT_EXTENSIBLE (0xFFFE) through as -2.
   */
  struct WaveFormatChunk
  {
    std::int16_t formatTag;       // +0x00
    std::uint16_t channels;       // +0x02
    std::uint32_t samplesPerSec;  // +0x04
    std::uint32_t avgBytesPerSec; // +0x08
    std::uint16_t blockAlign;     // +0x0C
    std::uint16_t bitsPerSample;  // +0x0E
  };
  static_assert(sizeof(WaveFormatChunk) == 0x10);

  /** The SPSD header fields `ADX_DecodeInfoSpsd` reads. */
  struct SpsdHeader
  {
    char magic[4];                     // +0x00  "SPSD"
    std::uint8_t mUnknown04[3];        // +0x04
    std::uint8_t headerParagraphs;     // +0x07  header length in 16-byte units
    std::uint8_t encoding;             // +0x08  0 PCM16, 1 PCM8, 2/3 4-bit
    std::uint8_t channelMode;          // +0x09  low two bits: channels - 1
    std::uint8_t mUnknown0A[2];        // +0x0A
    std::int32_t dataBytes;            // +0x0C
    std::uint8_t mUnknown10[0x1A];     // +0x10
    std::uint16_t sampleRate;          // +0x2A
  };
  static_assert(offsetof(SpsdHeader, headerParagraphs) == 0x07);
  static_assert(offsetof(SpsdHeader, dataBytes) == 0x0C);
  static_assert(offsetof(SpsdHeader, sampleRate) == 0x2A);

  [[nodiscard]] constexpr std::int16_t MuLawToPcm16(const std::uint8_t sample)
  {
    const auto normalized = static_cast<std::uint8_t>(~sample);
    const std::int32_t exponent = (normalized >> 4) & 0x07;
    const std::int32_t mantissa = normalized & 0x0F;
    const std::int32_t magnitude = (((mantissa << 3) + 0x84) << exponent) - 0x84;
    return static_cast<std::int16_t>((normalized & 0x80) != 0 ? -magnitude : magnitude);
  }

  [[nodiscard]] constexpr std::array<std::int16_t, 256> BuildMuLawTable()
  {
    std::array<std::int16_t, 256> table{};
    for (std::size_t sample = 0; sample < table.size(); ++sample) {
      table[sample] = MuLawToPcm16(static_cast<std::uint8_t>(sample));
    }
    return table;
  }

  /**
   * u-law expansion table the AU executor indexes (0x00F484A8 in the shipped
   * binary). Built from the G.711 expansion rule; all 256 entries were
   * compared against the binary's table and match.
   */
  constexpr std::array<std::int16_t, 256> kMuLawToPcm16 = BuildMuLawTable();

  /** Sample conversions the PCM executors instantiate `ExecutePcmSpan` with. */
  struct PcmFromLittleEndian16
  {
    [[nodiscard]] std::int16_t operator()(const std::int16_t sample) const { return sample; }
  };

  struct PcmFromBigEndian16
  {
    [[nodiscard]] std::int16_t operator()(const std::uint16_t sample) const
    {
      return static_cast<std::int16_t>(static_cast<std::uint16_t>((sample << 8) | (sample >> 8)));
    }
  };

  struct PcmFromSigned8
  {
    [[nodiscard]] std::int16_t operator()(const std::uint8_t sample) const
    {
      return static_cast<std::int16_t>(sample << 8);
    }
  };

  struct PcmFromUnsigned8
  {
    [[nodiscard]] std::int16_t operator()(const std::uint8_t sample) const
    {
      return static_cast<std::int16_t>((static_cast<std::int32_t>(sample) - 128) << 8);
    }
  };

  struct PcmFromMuLaw
  {
    [[nodiscard]] std::int16_t operator()(const std::uint8_t sample) const { return kMuLawToPcm16[sample]; }
  };

  /**
   * Asks the decoder's owner where the next span goes and returns how many
   * sample frames fit: bounded by the room left in the PCM ring, by the owner's
   * window, and by the frames left in the input span.
   */
  [[nodiscard]] std::int32_t AcquireWriteWindow(moho::AdxBitstreamDecoderState& decoder)
  {
    decoder.getWriteFunc(
      decoder.getWriteContext,
      &decoder.writeSampleIndex,
      &decoder.writableSamples,
      &decoder.samplesUntilTrap
    );
    return std::min(
      std::min(decoder.outputBufferSamples - decoder.writeSampleIndex, decoder.writableSamples),
      decoder.inputBlockCount
    );
  }

  /** Records one decoded span and moves the decoder to "span decoded". */
  void MarkSpanDecoded(moho::AdxBitstreamDecoderState& decoder, const std::int32_t samples, const std::int32_t bytes)
  {
    decoder.lastDecodedSamples = samples;
    decoder.lastDecodedBytes = bytes;
    decoder.status = 2;
  }

  /** Hands a decoded span to the owner's add-write callback, once. */
  std::int32_t CommitDecodedSpan(moho::AdxBitstreamDecoderState& decoder)
  {
    std::int32_t result = 0;
    if (decoder.status == 2) {
      result = decoder.addWriteFunc(decoder.addWriteContext, decoder.lastDecodedBytes, decoder.lastDecodedSamples);
      decoder.status = 3;
    }
    return result;
  }

  /**
   * One PCM decode step. CRI repeats this body in every PCM executor (WAV,
   * AU, AIFF, SPSD) with only the source sample type and its conversion
   * differing, so each executor is one instantiation: take a write window,
   * de-interleave the input frames into the channel planes of the PCM ring,
   * and commit the span.
   */
  template <typename SourceSample, typename ToPcm16>
  std::int32_t ExecutePcmSpan(moho::AdxBitstreamDecoderState& decoder, const ToPcm16 toPcm16)
  {
    if (decoder.status == 1 && ADXPD_GetStat(decoder.adxPacketDecoder) == 0) {
      const std::int32_t frames = AcquireWriteWindow(decoder);
      const auto* const source = reinterpret_cast<const SourceSample*>(decoder.inputData);
      std::int16_t* const left = decoder.outputBuffer + decoder.writeSampleIndex;

      if (decoder.sourceChannels == 2) {
        std::int16_t* const right = left + decoder.outputChannelStride;
        for (std::int32_t frame = 0; frame < frames; ++frame) {
          left[frame] = toPcm16(source[2 * frame]);
          right[frame] = toPcm16(source[2 * frame + 1]);
        }
      } else {
        for (std::int32_t frame = 0; frame < frames; ++frame) {
          left[frame] = toPcm16(source[frame]);
        }
      }

      const auto sourceBytes = static_cast<std::int32_t>(sizeof(SourceSample)) * frames * decoder.sourceChannels;
      MarkSpanDecoded(decoder, frames, sourceBytes);
    }
    return CommitDecodedSpan(decoder);
  }

  /**
   * The output lanes every PCM header decoder latches once its info parser
   * accepted the header: the source shape becomes the output shape, the PCM
   * ring from `ADXB_Create` becomes the active output, loop state and the
   * default callbacks' counters restart.
   */
  void LatchPcmOutput(moho::AdxBitstreamDecoderState& decoder)
  {
    decoder.outputChannels = decoder.sourceChannels;
    decoder.outputBlockBytes = decoder.sourceBlockBytes;
    decoder.outputBlockSamples = decoder.sourceBlockSamples;
    decoder.outputBuffer = decoder.pcmBuffer;
    decoder.outputBufferSamples = decoder.pcmBufferSamples;
    decoder.outputChannelStride = decoder.pcmChannelStride;
    decoder.adpcmCoefficientIndex = 0;
    decoder.loopType = 0;
    decoder.loopCount = 0;
    decoder.loopEndOffset = 0;
    decoder.loopEndSample = 0;
    decoder.loopStartOffset = 0;
    decoder.loopStartSample = 0;
    decoder.loopInsertedSamples = 0;
    decoder.bufferedSampleCount = 0;
    decoder.decodedSampleTotal = 0;
  }

  [[nodiscard]] bool FourCcEquals(const std::uint8_t* bytes, const char tag[4])
  {
    return std::memcmp(bytes, tag, 4u) == 0;
  }

  /**
   * First byte offset below `headerSize` holding `tag`, or `headerSize` when
   * there is none. Like the binary it compares a whole dword at every offset,
   * the last three included.
   */
  [[nodiscard]] std::int32_t FindWaveTag(const std::uint8_t* headerBytes, const std::int32_t headerSize, const char tag[4])
  {
    std::int32_t offset = 0;
    while (offset < headerSize && !FourCcEquals(headerBytes + offset, tag)) {
      ++offset;
    }
    return offset;
  }

  [[nodiscard]] int ComputeBlockBytes(std::int32_t channels, std::int32_t bitsPerSample)
  {
    return (channels * bitsPerSample) / 8;
  }

  /**
   * The body the three `ADXPD_Entry*` share: while the decoder is idle, queue
   * a block run and its output planes. Only the channel count differs.
   */
  [[nodiscard]] std::int32_t QueueBlockRun(
    moho::AdxPacketDecoder& decoder,
    char* const sourceData,
    const std::int32_t sourceBlockCount,
    std::uint16_t* const outputLeft,
    std::uint16_t* const outputRight,
    const std::int32_t channelCount
  )
  {
    if (decoder.status != 0) {
      return 0;
    }

    decoder.sourceData = sourceData;
    decoder.sourceBlockCount = sourceBlockCount;
    decoder.channelCount = channelCount;
    decoder.outputLeft = outputLeft;
    decoder.outputRight = outputRight;
    return 1;
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
    std::int32_t* outSampleRate,
    std::int32_t* outChannels,
    std::int32_t* outSampleBits,
    std::int32_t* outTotalSampleCount
  );
  std::int32_t adxpd_internal_error = 0;
  moho::AdxPacketDecoder adxpd_obj[32]{};
  std::int32_t xeci_thread_prio_2 = 0;
  XefindVisitCallback xeci_unk1_func = nullptr;
  void* xeci_unk1_func_obj = nullptr;
  LARGE_INTEGER xefind_last_scan_counter{};

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
   * Turns a caller buffer of at least 1 KiB into an empty arena whose header
   * occupies the buffer's start, with 4-byte alignment.
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
    auto* const manager = static_cast<HeapManager*>(heapBuffer);
    manager->arenaBase = static_cast<std::uint8_t*>(heapBuffer);
    manager->arenaBytes = heapByteCount;
    manager->alignment = 4;
    manager->head = nullptr;
    *outHeapManager = manager;
    return 0;
  }

  /**
   * Address: 0x00B27640 (_HEAPMNG_Destroy)
   *
   * What it does:
   * Clears the whole arena, header included.
   */
  std::int32_t __cdecl HEAPMNG_Destroy(void* heapManagerHandle)
  {
    if (heapManagerHandle == nullptr) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }

    const auto* const manager = static_cast<const HeapManager*>(heapManagerHandle);
    heapmng_clear(manager->arenaBase, manager->arenaBytes);
    return 0;
  }

  /**
   * Address: 0x00B276F0 (_heapmng_first_alloc)
   *
   * What it does:
   * Places the first block of an empty arena right after the arena header.
   */
  std::int32_t __cdecl heapmng_first_alloc(HeapManager* manager, const std::uint32_t byteCount, std::uint32_t* outAddress)
  {
    const std::uint32_t span = manager->SpanFor(byteCount);
    if (span > manager->arenaBytes - kHeapHeaderBytes) {
      heapmng_debug_log(kHeapOutOfMemoryMessage);
      return -1;
    }

    HeapManagerBlock* const block = manager->PlaceBlock(kHeapHeaderBytes, span, nullptr, nullptr);
    manager->head = block;
    *outAddress = block->userAddress;
    return 0;
  }

  /**
   * Address: 0x00B27760 (_heapmng_second_alloc)
   *
   * What it does:
   * First-fit placement in a populated arena: before the first block if the
   * gap after the arena header fits, else in the first gap between blocks that
   * fits, else appended after the last block.
   */
  std::int32_t __cdecl heapmng_second_alloc(HeapManager* manager, const std::uint32_t byteCount, std::uint32_t* outAddress)
  {
    *outAddress = 0;
    const std::uint32_t span = manager->SpanFor(byteCount);
    HeapManagerBlock* cursor = manager->head;

    if (cursor->startOffset - kHeapHeaderBytes > span) {
      HeapManagerBlock* const block = manager->PlaceBlock(kHeapHeaderBytes, span, nullptr, cursor);
      manager->head = block;
      cursor->prev = block;
      *outAddress = block->userAddress;
      return 0;
    }

    for (HeapManagerBlock* next = cursor->next; next != nullptr; cursor = next, next = cursor->next) {
      const std::uint32_t gapEnd = cursor->startOffset + cursor->spanBytes;
      if (span < next->startOffset - gapEnd) {
        HeapManagerBlock* const block = manager->PlaceBlock(gapEnd, span, cursor, next);
        cursor->next = block;
        next->prev = block;
        *outAddress = block->userAddress;
        return 0;
      }
    }

    const std::uint32_t tailOffset = cursor->startOffset + cursor->spanBytes;
    if (tailOffset + span >= manager->arenaBytes) {
      heapmng_debug_log(kHeapOutOfMemoryMessage);
      return -1;
    }

    HeapManagerBlock* const block = manager->PlaceBlock(tailOffset, span, cursor, nullptr);
    cursor->next = block;
    *outAddress = block->userAddress;
    return 0;
  }

  /**
   * Address: 0x00B27670 (_HEAPMNG_Allocate)
   *
   * What it does:
   * Allocates `byteCount` bytes from the arena. `*outPointer` is zeroed first,
   * so it stays zero when the arena is full.
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

    *outPointer = 0;
    HeapManager* const manager = HeapManagerFromHandle(heapManagerHandle);
    std::uint32_t address = 0;
    const std::int32_t result = (manager->head == nullptr)
      ? heapmng_first_alloc(manager, static_cast<std::uint32_t>(byteCount), &address)
      : heapmng_second_alloc(manager, static_cast<std::uint32_t>(byteCount), &address);
    if (result < 0) {
      return result;
    }

    *outPointer = static_cast<int>(address);
    return 0;
  }

  /**
   * Address: 0x00B279C0 (sub_B279C0)
   *
   * What it does:
   * Finds the block that handed out `userAddress`.
   */
  std::int32_t __cdecl heapmng_find_block_by_user_pointer(
    HeapManager* manager,
    const std::uint32_t userAddress,
    HeapManagerBlock** outBlock
  )
  {
    for (HeapManagerBlock* block = manager->head; block != nullptr; block = block->next) {
      if (block->userAddress == userAddress) {
        *outBlock = block;
        return 0;
      }
    }

    heapmng_debug_log(kHeapIllegalAddressMessage);
    return -1;
  }

  /**
   * Address: 0x00B27A00 (_HEAPMNG_Free)
   *
   * What it does:
   * Unlinks the block that handed out `pointerValue`; the arena bytes simply
   * become a gap for later first-fit placement.
   */
  std::int32_t __cdecl HEAPMNG_Free(int heapManagerHandle, int pointerValue)
  {
    if (heapManagerHandle == 0 || pointerValue == 0) {
      heapmng_debug_log(kHeapNullPointerMessage);
      return -1;
    }

    HeapManager* const manager = HeapManagerFromHandle(heapManagerHandle);
    HeapManagerBlock* block = manager->head;
    while (block != nullptr && block->userAddress != static_cast<std::uint32_t>(pointerValue)) {
      block = block->next;
    }
    if (block == nullptr) {
      heapmng_debug_log(kHeapIllegalAddressMessage);
      return -1;
    }

    HeapManagerBlock* const prev = block->prev;
    HeapManagerBlock* const next = block->next;
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
   * Resizes an allocation in place when its address is aligned and either its
   * own span or the gap up to the next block fits; otherwise allocates, copies
   * `byteCount` bytes and frees the old block.
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

    auto* const manager = static_cast<HeapManager*>(heapManagerHandle);
    const auto currentAddress = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(currentPointer));
    *outPointer = 0;

    HeapManagerBlock* block = nullptr;
    std::int32_t result = heapmng_find_block_by_user_pointer(manager, currentAddress, &block);
    if (result < 0) {
      return result;
    }

    const std::uint32_t span = manager->SpanFor(byteCount);
    if (currentAddress % manager->alignment == 0u) {
      if (span <= block->spanBytes) {
        block->spanBytes = span;
        *outPointer = currentAddress;
        return 0;
      }

      const HeapManagerBlock* const next = block->next;
      if (next != nullptr && next->startOffset - block->startOffset > span) {
        block->spanBytes = span;
        *outPointer = currentAddress;
        return 0;
      }
    }

    const auto handle = static_cast<int>(reinterpret_cast<std::uintptr_t>(heapManagerHandle));
    int newPointer = 0;
    result = HEAPMNG_Allocate(handle, static_cast<SIZE_T>(byteCount), &newPointer);
    if (result < 0) {
      *outPointer = currentAddress;
      return result;
    }

    heapmng_copy(reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(newPointer))), currentPointer, byteCount);
    result = HEAPMNG_Free(handle, static_cast<int>(currentAddress));
    if (result < 0) {
      return result;
    }

    *outPointer = static_cast<std::uint32_t>(newPointer);
    return 0;
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
   * Clears the ADX packet-decoder pool.
   */
  void ADXPD_Init()
  {
    std::memset(adxpd_obj, 0, sizeof(adxpd_obj));
  }

  /**
   * Address: 0x00B27D60 (_ADXPD_Finish)
   *
   * What it does:
   * Clears the ADX packet-decoder pool.
   */
  void ADXPD_Finish()
  {
    std::memset(adxpd_obj, 0, sizeof(adxpd_obj));
  }

  /**
   * Address: 0x00B27D80 (_ADXPD_Create)
   *
   * What it does:
   * Claims the first free pool slot, resets it, and selects the 500 Hz /
   * 44.1 kHz predictor coefficients; null when the pool is full.
   */
  moho::AdxPacketDecoder* ADXPD_Create()
  {
    for (std::int32_t slotIndex = 0; slotIndex < 32; ++slotIndex) {
      moho::AdxPacketDecoder& decoder = adxpd_obj[slotIndex];
      if (decoder.used == 0) {
        std::memset(&decoder, 0, sizeof(decoder));
        decoder.slotIndex = slotIndex;
        decoder.used = 1;
        decoder.mode = 0;
        decoder.status = 0;
        ADX_GetCoefficient(500, 44100, &decoder.coefficient0, &decoder.coefficient1);
        std::memset(decoder.delay, 0, sizeof(decoder.delay));
        return &decoder;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B27E00 (_ADXPD_SetCoef)
   *
   * What it does:
   * Selects the predictor coefficients for a cutoff index and sample rate.
   */
  std::int32_t ADXPD_SetCoef(moho::AdxPacketDecoder* decoder, std::int32_t sampleRate, std::int16_t coefficientIndex)
  {
    return ADX_GetCoefficient(coefficientIndex, sampleRate, &decoder->coefficient0, &decoder->coefficient1);
  }

  /**
   * Address: 0x00B27E20 (_ADXPD_SetDly)
   *
   * What it does:
   * Loads the predictor history: `delay0[ch]` is each channel's previous
   * sample, `delay1[ch]` the one before.
   */
  moho::AdxPacketDecoder* ADXPD_SetDly(moho::AdxPacketDecoder* decoder, const std::int16_t* delay0, const std::int16_t* delay1)
  {
    for (std::size_t channel = 0; channel < 2; ++channel) {
      decoder->delay[channel][0] = delay0[channel];
      decoder->delay[channel][1] = delay1[channel];
    }
    return decoder;
  }

  /**
   * Address: 0x00B27E50 (_ADXPD_GetDly)
   *
   * What it does:
   * Reads the predictor history back in `ADXPD_SetDly` form.
   */
  void ADXPD_GetDly(const moho::AdxPacketDecoder* decoder, std::int16_t* outDelay0, std::int16_t* outDelay1)
  {
    for (std::size_t channel = 0; channel < 2; ++channel) {
      outDelay0[channel] = decoder->delay[channel][0];
      outDelay1[channel] = decoder->delay[channel][1];
    }
  }

  /**
   * Address: 0x00B27E80 (_ADXPD_SetExtPrm)
   *
   * What it does:
   * Loads the key stream: start value, multiplier, adder.
   */
  moho::AdxPacketDecoder*
  ADXPD_SetExtPrm(moho::AdxPacketDecoder* decoder, std::int16_t key0, std::int16_t keyMultiplier, std::int16_t keyAdder)
  {
    decoder->key = static_cast<std::uint16_t>(key0);
    decoder->keyMultiplier = keyMultiplier;
    decoder->keyAdder = keyAdder;
    return decoder;
  }

  /**
   * Address: 0x00B27EA0 (_ADXPD_GetExtPrm)
   *
   * What it does:
   * Reads the key stream back.
   */
  std::int16_t ADXPD_GetExtPrm(
    const moho::AdxPacketDecoder* decoder,
    std::int16_t* outKey0,
    std::int16_t* outKeyMultiplier,
    std::int16_t* outKeyAdder
  )
  {
    *outKey0 = static_cast<std::int16_t>(decoder->key);
    *outKeyMultiplier = decoder->keyMultiplier;
    *outKeyAdder = decoder->keyAdder;
    return decoder->keyAdder;
  }

  /**
   * Address: 0x00B27ED0 (_ADXPD_Destroy)
   *
   * What it does:
   * Releases one packet decoder's pool slot.
   */
  void ADXPD_Destroy(moho::AdxPacketDecoder* decoder)
  {
    if (decoder == nullptr) {
      return;
    }

    decoder->used = 0;
    std::memset(decoder, 0, sizeof(*decoder));
  }

  /**
   * Address: 0x00B27EF0 (_ADXPD_SetMode)
   *
   * What it does:
   * Stores the decode mode.
   */
  std::int32_t ADXPD_SetMode(moho::AdxPacketDecoder* decoder, std::int32_t mode)
  {
    decoder->mode = mode;
    return mode;
  }

  /**
   * Address: 0x00B27F00 (_ADXPD_GetStat)
   *
   * What it does:
   * Returns the packet decoder's status.
   */
  std::int32_t ADXPD_GetStat(const moho::AdxPacketDecoder* decoder)
  {
    return decoder->status;
  }

  /**
   * Address: 0x00B27F10 (_ADXPD_EntryMono)
   *
   * What it does:
   * Queues a mono block run while idle.
   */
  std::int32_t __cdecl ADXPD_EntryMono(
    moho::AdxPacketDecoder* decoder,
    char* sourceData,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    return QueueBlockRun(*decoder, sourceData, sourceBlockCount, outputLeft, outputRight, 1);
  }

  /**
   * Address: 0x00B27F50 (_ADXPD_EntryPl2)
   *
   * What it does:
   * Queues a stereo-interleaved (Pro Logic II) block run while idle.
   */
  std::int32_t __cdecl ADXPD_EntryPl2(
    moho::AdxPacketDecoder* decoder,
    char* sourceData,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    return QueueBlockRun(*decoder, sourceData, sourceBlockCount, outputLeft, outputRight, 2);
  }

  /**
   * Address: 0x00B27F90 (_ADXPD_EntrySte)
   *
   * What it does:
   * Queues a single-channel block run decoded into both planes while idle.
   */
  std::int32_t __cdecl ADXPD_EntrySte(
    moho::AdxPacketDecoder* decoder,
    char* sourceData,
    std::int32_t sourceBlockCount,
    std::uint16_t* outputLeft,
    std::uint16_t* outputRight
  )
  {
    return QueueBlockRun(*decoder, sourceData, sourceBlockCount, outputLeft, outputRight, 1);
  }

  /**
   * Address: 0x00B27FD0 (_ADXPD_Start)
   *
   * What it does:
   * Moves an idle decoder to "queued" and clears its block count.
   */
  moho::AdxPacketDecoder* ADXPD_Start(moho::AdxPacketDecoder* decoder)
  {
    if (decoder->status == 0) {
      decoder->decodedBlockCount = 0;
      decoder->status = 1;
    }
    return decoder;
  }

  /**
   * Address: 0x00B27FF0 (_ADXPD_Stop)
   *
   * What it does:
   * Stops the decoder and clears the predictor history.
   */
  std::int16_t* ADXPD_Stop(moho::AdxPacketDecoder* decoder)
  {
    decoder->status = 0;
    std::memset(decoder->delay, 0, sizeof(decoder->delay));
    return decoder->delay[0];
  }

  /**
   * Address: 0x00B28010 (_ADXPD_Reset)
   *
   * What it does:
   * Returns a finished decoder to idle.
   */
  moho::AdxPacketDecoder* ADXPD_Reset(moho::AdxPacketDecoder* decoder)
  {
    if (decoder->status == 3) {
      decoder->status = 0;
    }
    return decoder;
  }

  /**
   * Address: 0x00B28030 (_ADXPD_GetNumBlk)
   *
   * What it does:
   * Returns the blocks the last run decoded.
   */
  std::int32_t ADXPD_GetNumBlk(const moho::AdxPacketDecoder* decoder)
  {
    return decoder->decodedBlockCount;
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
   * Decodes the queued run: mono runs through `ADX_DecodeMono4`, everything
   * else through `ADX_DecodeSte4`, which must consume blocks in pairs; an odd
   * count latches the internal-error flag.
   */
  void __cdecl ADXPD_ExecHndl(moho::AdxPacketDecoder* decoder)
  {
    if (decoder->status == 1) {
      decoder->status = 2;
    }
    if (decoder->status != 2) {
      return;
    }

    if (decoder->channelCount == 1) {
      decoder->decodedBlockCount = ADX_DecodeMono4(
        decoder->sourceData,
        decoder->sourceBlockCount,
        decoder->outputLeft,
        decoder->delay[0],
        decoder->coefficient0,
        decoder->coefficient1,
        &decoder->key,
        decoder->keyMultiplier,
        decoder->keyAdder
      );
      decoder->status = 3;
      return;
    }

    decoder->decodedBlockCount = ADX_DecodeSte4(
      decoder->sourceData,
      decoder->sourceBlockCount,
      decoder->outputLeft,
      decoder->delay[0],
      decoder->outputRight,
      decoder->delay[1],
      decoder->coefficient0,
      decoder->coefficient1,
      &decoder->key,
      decoder->keyMultiplier,
      decoder->keyAdder
    );
    if (decoder->decodedBlockCount % 2 == 1) {
      adxpd_error();
    }
    decoder->status = 3;
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
    std::int16_t* outHeaderBytes,
    std::int8_t* outHeaderType,
    std::int8_t* outSampleBits,
    std::int8_t* outBlockBytes,
    std::int8_t* outChannels,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outBlockSamples,
    std::int32_t* outPackingMode
  )
  {
    if (headerSize < 8) {
      *outHeaderBytes = 0;
      return -1;
    }

    std::int32_t sampleRate = 0;
    std::int32_t channels = 0;
    std::int32_t sampleBits = 0;
    std::int32_t totalSampleCount = 0;
    const std::uint8_t* const streamData = AU_GetInfo(
      headerBytes, headerSize, &sampleRate, &channels, &sampleBits, &totalSampleCount, outPackingMode
    );
    if (streamData == nullptr) {
      return -1;
    }

    *outHeaderBytes = static_cast<std::int16_t>(streamData - headerBytes);
    if (*outHeaderBytes <= 0) {
      return -1;
    }

    *outSampleRate = sampleRate;
    *outChannels = static_cast<std::int8_t>(channels);
    *outSampleBits = static_cast<std::int8_t>(sampleBits);
    *outTotalSampleCount = totalSampleCount;
    *outHeaderType = -1;
    *outBlockBytes = static_cast<std::int8_t>(ComputeBlockBytes(*outChannels, *outSampleBits));
    *outBlockSamples = 1;
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
    std::int16_t headerBytesConsumed = 0;
    std::int32_t packingMode = 0;

    decoder->initState = 1;
    if (ADX_DecodeInfoAu(
          const_cast<std::uint8_t*>(headerBytes),
          headerSize,
          &headerBytesConsumed,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceBlockBytes,
          &decoder->sourceChannels,
          &decoder->sampleRate,
          &decoder->totalSampleCount,
          &decoder->sourceBlockSamples,
          &packingMode
        ) < 0) {
      return 0;
    }

    LatchPcmOutput(*decoder);
    decoder->format = 4;
    decoder->outputSamplePacking = static_cast<std::int16_t>(packingMode);
    return headerBytesConsumed;
  }

  /**
   * Address: 0x00B28540 (_ADXB_ExecOneAu16)
   *
   * What it does:
   * Decodes one span of big-endian 16-bit AU samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneAu16(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint16_t>(*decoder, PcmFromBigEndian16{});
  }

  /**
   * Address: 0x00B28660 (_ADXB_ExecOneAu8)
   *
   * What it does:
   * Decodes one span of signed 8-bit AU samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneAu8(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint8_t>(*decoder, PcmFromSigned8{});
  }

  /**
   * Address: 0x00B28760 (_ADXB_ExecOneAuUlaw)
   *
   * What it does:
   * Decodes one span of u-law AU samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneAuUlaw(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint8_t>(*decoder, PcmFromMuLaw{});
  }

  /**
   * Address: 0x00B28870 (_ADXB_ExecOneAu)
   *
   * What it does:
   * Dispatches the AU executor by sample packing.
   */
  int __cdecl ADXB_ExecOneAu(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->outputSamplePacking == 2) {
      return ADXB_ExecOneAuUlaw(decoder);
    }
    if (decoder->outputSamplePacking == 1) {
      return ADXB_ExecOneAu8(decoder);
    }
    return ADXB_ExecOneAu16(decoder);
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
    std::int16_t* outHeaderBytes,
    std::int8_t* outHeaderType,
    std::int8_t* outSampleBits,
    std::int8_t* outBlockBytes,
    std::int8_t* outChannels,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outBlockSamples
  )
  {
    if (headerSize < 0x1000) {
      *outHeaderBytes = 0;
      return -1;
    }

    std::int32_t sampleRate = 0;
    std::int32_t channels = 0;
    std::int32_t sampleBits = 0;
    std::int32_t totalSampleCount = 0;
    const std::uint8_t* const streamData =
      AIFF_GetInfo(headerBytes, &sampleRate, &channels, &sampleBits, &totalSampleCount);
    if (streamData == nullptr) {
      return -1;
    }

    *outHeaderBytes = static_cast<std::int16_t>(streamData - headerBytes);
    if (*outHeaderBytes <= 0) {
      return -1;
    }

    *outSampleRate = sampleRate;
    *outChannels = static_cast<std::int8_t>(channels);
    *outSampleBits = static_cast<std::int8_t>(sampleBits);
    *outTotalSampleCount = totalSampleCount;
    *outHeaderType = -1;
    *outBlockBytes = static_cast<std::int8_t>(ComputeBlockBytes(*outChannels, *outSampleBits));
    *outBlockSamples = 1;
    return 0;
  }

  /**
   * Address: 0x00B28990 (_AIFF_GetInfo)
   *
   * What it does:
   * Walks the AIFF `FORM` chunk list for `COMM` (channels, frame count,
   * sample size, rate) and `SSND` (sample data), returning the sample data
   * once both were seen, or whatever was found when the form ends.
   */
  std::uint8_t* AIFF_GetInfo(
    std::uint8_t* sourceBytes,
    std::int32_t* outSampleRate,
    std::int32_t* outChannels,
    std::int32_t* outSampleBits,
    std::int32_t* outTotalSampleCount
  )
  {
    if (!ADXB_CheckAiff(sourceBytes)) {
      return nullptr;
    }

    std::uint8_t* cursor = sourceBytes + 12;
    const std::uint8_t* const formEnd = cursor + ReadBe32(sourceBytes + 4) - 4;
    const std::uint32_t ssndId = ReadBe32(reinterpret_cast<const std::uint8_t*>(kAiffChunkSsnd));
    const std::uint32_t commId = ReadBe32(reinterpret_cast<const std::uint8_t*>(kAiffChunkComm));

    std::uint8_t* streamData = nullptr;
    bool foundSsnd = false;
    bool foundComm = false;
    while (cursor < formEnd) {
      const std::uint32_t chunkId = ReadBe32(cursor);
      const auto chunkSize = static_cast<std::int32_t>(ReadBe32(cursor + 4));
      cursor += 8;

      if (chunkId == ssndId) {
        if (!foundSsnd) {
          const std::uint32_t dataOffset = ReadBe32(cursor);
          cursor += 4;
          foundSsnd = true;
          streamData = cursor + dataOffset;
          if (foundComm) {
            return streamData;
          }
        }
      } else if (chunkId == commId) {
        if (!foundComm) {
          if (chunkSize < 18) {
            return nullptr;
          }

          *outChannels = ReadBe16(cursor);
          *outTotalSampleCount = static_cast<std::int32_t>(ReadBe32(cursor + 2));
          *outSampleBits = ReadBe16(cursor + 6);

          // The 80-bit extended sample rate, reduced to its top mantissa word
          // shifted by the low exponent byte (x86 masks the count to 5 bits).
          const auto shift = static_cast<std::uint8_t>(14u - cursor[9]) & 0x1Fu;
          *outSampleRate = static_cast<std::int32_t>(ReadBe16(cursor + 10) >> shift);

          cursor += 18;
          foundComm = true;
          if (foundSsnd) {
            return streamData;
          }
        }
      } else {
        cursor += (chunkSize + 1) & ~1;
      }
    }

    return streamData;
  }

  /**
   * Address: 0x00B28C30 (_ADXB_DecodeHeaderAiff)
   *
   * What it does:
   * Decodes an AIFF header into the decoder and latches the PCM output; 8-bit
   * sources use signed-byte packing, everything else big-endian 16-bit.
   */
  int ADXB_DecodeHeaderAiff(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    std::int32_t headerSize
  )
  {
    std::int16_t headerBytesConsumed = 0;

    decoder->initState = 1;
    if (ADX_DecodeInfoAiff(
          const_cast<std::uint8_t*>(headerBytes),
          headerSize,
          &headerBytesConsumed,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceBlockBytes,
          &decoder->sourceChannels,
          &decoder->sampleRate,
          &decoder->totalSampleCount,
          &decoder->sourceBlockSamples
        ) < 0) {
      return 0;
    }

    LatchPcmOutput(*decoder);
    decoder->format = 3;
    decoder->outputSamplePacking = (decoder->sourceSampleBits == 8) ? 1 : 0;
    return headerBytesConsumed;
  }

  /**
   * Address: 0x00B28D00 (_ADXB_ExecOneAiff16)
   *
   * What it does:
   * Decodes one span of big-endian 16-bit AIFF samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneAiff16(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint16_t>(*decoder, PcmFromBigEndian16{});
  }

  /**
   * Address: 0x00B28E20 (_ADXB_ExecOneAiff8)
   *
   * What it does:
   * Decodes one span of signed 8-bit AIFF samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneAiff8(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint8_t>(*decoder, PcmFromSigned8{});
  }

  /**
   * Address: 0x00B28F20 (_ADXB_ExecOneAiff)
   *
   * What it does:
   * Dispatches the AIFF executor by sample packing.
   */
  int __cdecl ADXB_ExecOneAiff(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->outputSamplePacking == 1) {
      return ADXB_ExecOneAiff8(decoder);
    }
    return ADXB_ExecOneAiff16(decoder);
  }

  /**
   * Address: 0x00B28F40 (_ADX_DecodeInfoWav)
   *
   * What it does:
   * Finds the `fmt ` and `data` chunks of a RIFF/WAVE header and derives the
   * decoder's stream shape from them. 4-bit sources are consumed as 16-bit
   * frames of four samples.
   */
  int __cdecl ADX_DecodeInfoWav(
    const std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderBytes,
    std::int8_t* outHeaderType,
    std::int8_t* outSampleBits,
    std::int8_t* outBlockBytes,
    std::int8_t* outChannels,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outBlockSamples,
    std::int16_t* outPackingMode
  )
  {
    const std::int32_t formatOffset = FindWaveTag(headerBytes, headerSize, kFormatTag);
    if (formatOffset == headerSize || formatOffset % 4 != 0) {
      return -1;
    }

    const auto& format =
      *reinterpret_cast<const WaveFormatChunk*>(headerBytes + formatOffset + sizeof(RiffChunkHeader));
    if (format.formatTag > 1) {
      return -1;
    }

    const std::int32_t dataOffset = FindWaveTag(headerBytes, headerSize, kDataTag);
    if (dataOffset == headerSize) {
      return -1;
    }

    const auto dataBytes =
      static_cast<std::int32_t>(reinterpret_cast<const RiffChunkHeader*>(headerBytes + dataOffset)->size);
    *outHeaderBytes = static_cast<std::int16_t>(dataOffset + sizeof(RiffChunkHeader));
    *outHeaderType = -1;
    *outSampleRate = static_cast<std::int32_t>(format.samplesPerSec);
    *outChannels = static_cast<std::int8_t>(format.channels);
    *outSampleBits = static_cast<std::int8_t>(format.bitsPerSample);
    *outBlockBytes = static_cast<std::int8_t>(format.blockAlign);
    *outTotalSampleCount = dataBytes / *outBlockBytes;
    *outBlockSamples = 1;

    if (*outSampleBits == 16) {
      *outPackingMode = 0;
    } else if (*outSampleBits == 8) {
      *outPackingMode = 1;
    } else if (*outSampleBits == 4) {
      *outBlockBytes = static_cast<std::int8_t>(2 * *outChannels);
      *outBlockSamples = 4;
      *outTotalSampleCount = dataBytes / 2 / *outChannels;
      *outSampleBits = 16;
      *outPackingMode = 2;
    }

    if (*outSampleBits == 0 || *outBlockBytes == 0 || *outChannels <= 0 || *outChannels > 2) {
      return -1;
    }
    return (*outSampleRate != 0) ? 0 : -1;
  }

  /**
   * Address: 0x00B29090 (_ADXB_DecodeHeaderWav)
   *
   * What it does:
   * Decodes a WAV header into the decoder and latches the PCM output.
   */
  int ADXB_DecodeHeaderWav(
    moho::AdxBitstreamDecoderState* decoder,
    const std::uint8_t* headerBytes,
    std::int32_t headerSize
  )
  {
    std::int16_t headerBytesConsumed = 0;

    decoder->initState = 1;
    if (ADX_DecodeInfoWav(
          headerBytes,
          headerSize,
          &headerBytesConsumed,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceBlockBytes,
          &decoder->sourceChannels,
          &decoder->sampleRate,
          &decoder->totalSampleCount,
          &decoder->sourceBlockSamples,
          &decoder->outputSamplePacking
        ) < 0) {
      return 0;
    }

    LatchPcmOutput(*decoder);
    decoder->format = 1;
    return headerBytesConsumed;
  }

  /**
   * Address: 0x00B29150 (_ADXB_ExecOneWav16)
   *
   * What it does:
   * Decodes one span of little-endian 16-bit WAV samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneWav16(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::int16_t>(*decoder, PcmFromLittleEndian16{});
  }

  /**
   * Address: 0x00B29250 (_ADXB_ExecOneWav8)
   *
   * What it does:
   * Decodes one span of unsigned 8-bit WAV samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneWav8(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::uint8_t>(*decoder, PcmFromUnsigned8{});
  }

  /**
   * Address: 0x00B294E0 (_ADX_DecodeInfoSpsd)
   *
   * What it does:
   * Derives the stream shape from an SPSD header. Whatever encoding the header
   * names, the decoder consumes the payload as 16-bit frames.
   */
  int __cdecl ADX_DecodeInfoSpsd(
    const std::uint8_t* headerBytes,
    std::int32_t headerSize,
    std::int16_t* outHeaderBytes,
    std::int8_t* outHeaderType,
    std::int8_t* outSampleBits,
    std::int8_t* outBlockBytes,
    std::int8_t* outChannels,
    std::int32_t* outSampleRate,
    std::int32_t* outTotalSampleCount,
    std::int32_t* outBlockSamples,
    std::int16_t* outPackingMode
  )
  {
    (void)headerSize;
    const auto& header = *reinterpret_cast<const SpsdHeader*>(headerBytes);
    *outHeaderBytes = static_cast<std::int16_t>(16 * header.headerParagraphs);
    *outChannels = static_cast<std::int8_t>((header.channelMode & 3) + 1);
    *outSampleRate = header.sampleRate;

    switch (header.encoding) {
      case 0:
        *outSampleBits = 16;
        *outBlockBytes = static_cast<std::int8_t>(2 * *outChannels);
        *outBlockSamples = 1;
        *outTotalSampleCount = header.dataBytes / 2;
        *outPackingMode = 0;
        break;
      case 1:
        *outSampleBits = 8;
        *outBlockBytes = *outChannels;
        *outBlockSamples = 1;
        *outTotalSampleCount = header.dataBytes;
        *outPackingMode = 1;
        break;
      case 2:
      case 3:
        *outSampleBits = 4;
        *outBlockBytes = *outChannels;
        *outBlockSamples = 2;
        *outTotalSampleCount = 2 * header.dataBytes;
        *outPackingMode = 2;
        break;
      default:
        break;
    }

    *outBlockBytes = 2;
    *outBlockSamples = 1;
    *outTotalSampleCount = header.dataBytes / 2;
    *outSampleBits = 16;
    *outHeaderType = -1;
    return 0;
  }

  /**
   * Address: 0x00B295D0 (_ADXB_DecodeHeaderSpsd)
   *
   * What it does:
   * Decodes an SPSD header into the decoder and latches the PCM output.
   */
  int ADXB_DecodeHeaderSpsd(moho::AdxBitstreamDecoderState* decoder, const std::uint8_t* headerBytes, std::int32_t headerSize)
  {
    std::int16_t headerBytesConsumed = 0;

    decoder->initState = 1;
    if (ADX_DecodeInfoSpsd(
          headerBytes,
          headerSize,
          &headerBytesConsumed,
          &decoder->headerType,
          &decoder->sourceSampleBits,
          &decoder->sourceBlockBytes,
          &decoder->sourceChannels,
          &decoder->sampleRate,
          &decoder->totalSampleCount,
          &decoder->sourceBlockSamples,
          &decoder->outputSamplePacking
        ) < 0) {
      return 0;
    }

    LatchPcmOutput(*decoder);
    decoder->format = 2;
    return headerBytesConsumed;
  }

  /**
   * Address: 0x00B29360 (_ADXB_ExecOneWav4)
   *
   * What it does:
   * Decodes one span of the 4-bit WAV packing, which reaches the decoder as
   * 16-bit frames: mono frames are little-endian words, stereo frames
   * interleave the two channels byte by byte (L lo, R lo, L hi, R hi).
   */
  int __cdecl ADXB_ExecOneWav4(moho::AdxBitstreamDecoderState* decoder)
  {
    if (decoder->status == 1 && ADXPD_GetStat(decoder->adxPacketDecoder) == 0) {
      const std::int32_t frames = AcquireWriteWindow(*decoder);
      const auto* const source = reinterpret_cast<const std::uint8_t*>(decoder->inputData);
      std::int16_t* const left = decoder->outputBuffer + decoder->writeSampleIndex;

      if (decoder->sourceChannels == 2) {
        std::int16_t* const right = left + decoder->outputChannelStride;
        for (std::int32_t frame = 0; frame < frames; ++frame) {
          const std::uint8_t* const bytes = source + 4 * frame;
          left[frame] = static_cast<std::int16_t>(bytes[0] | (bytes[2] << 8));
          right[frame] = static_cast<std::int16_t>(bytes[1] | (bytes[3] << 8));
        }
      } else {
        for (std::int32_t frame = 0; frame < frames; ++frame) {
          const std::uint8_t* const bytes = source + 2 * frame;
          left[frame] = static_cast<std::int16_t>(bytes[0] | (bytes[1] << 8));
        }
      }

      MarkSpanDecoded(*decoder, frames, 2 * frames * decoder->sourceChannels);
    }
    return CommitDecodedSpan(*decoder);
  }

  /**
   * Address: 0x00B294A0 (_ADXB_ExecOneWav)
   *
   * What it does:
   * Dispatches the WAV executor by sample packing; an unknown packing does
   * nothing and hands the packing value back.
   */
  int __cdecl ADXB_ExecOneWav(moho::AdxBitstreamDecoderState* decoder)
  {
    switch (decoder->outputSamplePacking) {
      case 2:
        return ADXB_ExecOneWav4(decoder);
      case 1:
        return ADXB_ExecOneWav8(decoder);
      case 0:
        return ADXB_ExecOneWav16(decoder);
      default:
        return decoder->outputSamplePacking;
    }
  }

  /**
   * Address: 0x00B29690 (_ADXB_ExecOneSpsd)
   *
   * What it does:
   * Decodes one span of little-endian 16-bit SPSD samples into the PCM ring.
   */
  int __cdecl ADXB_ExecOneSpsd(moho::AdxBitstreamDecoderState* decoder)
  {
    return ExecutePcmSpan<std::int16_t>(*decoder, PcmFromLittleEndian16{});
  }
}
