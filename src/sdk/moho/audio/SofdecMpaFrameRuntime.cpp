#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C"
{
  int __cdecl mpabdr_GetBitVal8(std::uint8_t sourceByte, int bitOffset, int bitCount, int* outValue);

  extern std::int32_t mpadcd_bps_table[];
  extern std::int32_t mpadcd_freq_table[];
  extern std::int32_t mpadcd_jsb_table[];
  extern float mpadcd_division_table[];
  extern float mpadcd_dequantize_table_d[];
  extern float mpadcd_dequantize_denormze_table[];
  extern float mpadcd_synthesis_polyphase_seed_table[];
  extern float mpadcd_synthesis_filter_table[];
  extern float mpadcd_synthesis_window_table[];
  extern float mpadcd_synthesis_window_tail_table[];

  namespace
  {
    constexpr std::size_t kStateSyncErrorIndex = 437; // +0x6D4
    constexpr std::size_t kStateSyncCursorIndex = 438; // +0x6D8
    constexpr std::size_t kStateParsePhaseIndex = 439; // +0x6DC
    constexpr std::size_t kStateMpegVersionIndex = 440; // +0x6E0
    constexpr std::size_t kStateBitRateIndex = 441; // +0x6E4
    constexpr std::size_t kStateFrequencyIndex = 442; // +0x6E8
    constexpr std::size_t kStateCrcFlagIndex = 443; // +0x6EC
    constexpr std::size_t kStateChannelModeIndex = 444; // +0x6F0
    constexpr std::size_t kStateChannelCountIndex = 445; // +0x6F4
    constexpr std::size_t kStateJsBoundIndex = 446; // +0x6F8
    constexpr std::size_t kStateBandLimitIndex = 447; // +0x6FC
    constexpr std::size_t kStateEmphasisIndex = 448; // +0x700
    constexpr std::size_t kStateAllocTypeIndex = 449; // +0x704
    constexpr std::size_t kStateAllocLenTableIndex = 450; // +0x708

    constexpr std::size_t kStateBitAllocBaseIndex = 451; // +0x70C
    constexpr std::size_t kStateScaleFactorSelectBaseIndex = 515; // +0x80C
    constexpr std::size_t kStateScaleFactorBaseIndex = 579; // +0x90C
    constexpr std::size_t kStateDecodeTableDirectBaseIndex = 771; // +0xC0C
    constexpr std::size_t kStateDecodeTableGroupedBitsBaseIndex = 803; // +0xC8C
    constexpr std::size_t kStateDecodeTableGroupedBaseIndex = 835; // +0xD0C
    constexpr std::size_t kStateQuantizedSampleBaseIndex = 867; // +0xD8C
    constexpr std::size_t kStateDequantizedSampleBaseIndex = 1059; // +0x108C
    constexpr std::size_t kStateSynthesisRingCursorBaseIndex = 3299; // +0x338C
    constexpr std::size_t kStateSynthesisScaleCursorIndex = 3400; // +0x3520

    constexpr std::size_t kStatePcmOutputBytesOffset = 13204;
    constexpr std::size_t kStateSynthesisInputBytesOffset = 4236;
    constexpr std::size_t kStateSynthesisOutputBytesOffset = 5004;
    constexpr std::size_t kStateSynthesisOutputMirrorBytesOffset = 5132;
    constexpr std::size_t kStateSynthesisOutputUpperBytesOffset = 5136;
    constexpr std::size_t kStateSynthesisNegatedSumBytesOffset = 5196;
    constexpr std::size_t kStateSynthesisCopyBytesOffset = 5256;

    constexpr std::int32_t kMpaErrorMalformed = -21;
  } // namespace

  /**
   * Address: 0x00B29B90 (_mpadcd_ch_info_proc)
   *
   * What it does:
   * Resolves channel-count and JS-bound runtime lanes from MPEG mode.
   */
  int __cdecl mpadcd_ch_info_proc(std::uint32_t* state)
  {
    std::int32_t mode = static_cast<std::int32_t>(state[kStateChannelModeIndex]);
    std::int32_t jsBound = static_cast<std::int32_t>(state[kStateJsBoundIndex]);
    std::int32_t bandLimit = 0;
    std::int32_t channelCount = 0;

    if (mode == 0 || mode == 2) {
      bandLimit = 64;
      jsBound = 32;
      channelCount = 2;
    } else if (mode == 3) {
      channelCount = 1;
      bandLimit = 32;
      jsBound = 0;
    } else {
      bandLimit = jsBound + 32;
      channelCount = 2;
    }

    if (state[kStateChannelCountIndex] != 0 &&
        static_cast<std::int32_t>(state[kStateChannelCountIndex]) != channelCount) {
      return kMpaErrorMalformed;
    }

    state[kStateChannelCountIndex] = static_cast<std::uint32_t>(channelCount);
    state[kStateBandLimitIndex] = static_cast<std::uint32_t>(bandLimit);
    state[kStateJsBoundIndex] = static_cast<std::uint32_t>(jsBound);
    return 0;
  }

  /**
   * Address: 0x00B29C00 (_mpadcd_check_crc)
   *
   * What it does:
   * Applies CRC-skip cursor adjustment when MPEG header marks CRC present.
   */
  int __cdecl mpadcd_check_crc(std::uint32_t* state)
  {
    if (state[kStateMpegVersionIndex] == 1) {
      state[kStateSyncCursorIndex] += 2;
    }
    return 0;
  }

  /**
   * Address: 0x00B29C20 (_mpadcd_reset_dec_param)
   *
   * What it does:
   * Clears per-frame decode working sets before allocation/sample decode passes.
   */
  int __cdecl mpadcd_reset_dec_param(std::uint32_t* state)
  {
    state[kStateAllocTypeIndex] = 0;
    state[kStateAllocLenTableIndex] = 0;
    std::memset(state + kStateBitAllocBaseIndex, 0, 0x100u);
    std::memset(state + kStateScaleFactorSelectBaseIndex, 0, 0x100u);
    std::memset(state + kStateScaleFactorBaseIndex, 0, 0x300u);
    std::memset(state + kStateDecodeTableDirectBaseIndex, 0, 0x80u);
    std::memset(state + kStateDecodeTableGroupedBitsBaseIndex, 0, 0x80u);
    std::memset(state + kStateDecodeTableGroupedBaseIndex, 0, 0x80u);
    std::memset(state + kStateQuantizedSampleBaseIndex, 0, 0x300u);
    std::memset(state + kStateDequantizedSampleBaseIndex, 0, 0x300u);
    std::memset(state + kStateSynthesisRingCursorBaseIndex + 2, 0, 0x180u);
    state[kStateSynthesisScaleCursorIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B299C0 (_mpadcd_GetHdrInfo)
   *
   * What it does:
   * Parses MPEG frame header lanes and initializes channel/frame decode state.
   */
  int __cdecl mpadcd_GetHdrInfo(std::uint32_t* state)
  {
    auto* const headerBytes = reinterpret_cast<std::uint8_t*>(state);

    if (headerBytes[12] != 0xFF) {
      state[kStateSyncErrorIndex] = 0;
      state[kStateSyncCursorIndex] = 1;
      return kMpaErrorMalformed;
    }

    std::int32_t mpegVersion = 0;
    if (headerBytes[13] == 0xFC) {
      mpegVersion = 1;
    } else if (headerBytes[13] == 0xFD) {
      mpegVersion = 0;
    } else {
      state[kStateSyncErrorIndex] = 0;
      state[kStateSyncCursorIndex] = 1;
      return kMpaErrorMalformed;
    }

    int bitRateIndex = 0;
    mpabdr_GetBitVal8(headerBytes[14], 0, 4, &bitRateIndex);
    const auto bitRate = mpadcd_bps_table[bitRateIndex & 0xFF];

    int frequencyIndex = 0;
    mpabdr_GetBitVal8(headerBytes[14], 4, 2, &frequencyIndex);
    const auto frequency = mpadcd_freq_table[frequencyIndex & 0xFF];
    if (frequency <= 0) {
      state[kStateSyncErrorIndex] = 0;
      state[kStateSyncCursorIndex] = 1;
      return kMpaErrorMalformed;
    }

    int crcFlag = 0;
    int channelMode = 0;
    int jsBoundIndex = 0;
    int emphasis = 0;
    mpabdr_GetBitVal8(headerBytes[14], 6, 1, &crcFlag);
    mpabdr_GetBitVal8(headerBytes[15], 0, 2, &channelMode);
    mpabdr_GetBitVal8(headerBytes[15], 2, 2, &jsBoundIndex);
    mpabdr_GetBitVal8(headerBytes[15], 6, 2, &emphasis);

    const auto jsBound = mpadcd_jsb_table[jsBoundIndex & 0xFF];
    if (state[kStateFrequencyIndex] != 0 &&
        static_cast<std::int32_t>(state[kStateFrequencyIndex]) != frequency) {
      state[kStateSyncErrorIndex] = 0;
      state[kStateSyncCursorIndex] = 1;
      return kMpaErrorMalformed;
    }

    state[kStateMpegVersionIndex] = static_cast<std::uint32_t>(mpegVersion);
    state[kStateCrcFlagIndex] = static_cast<std::uint32_t>(crcFlag & 0xFF);
    state[kStateParsePhaseIndex] = 2;
    state[kStateBitRateIndex] = static_cast<std::uint32_t>(bitRate);
    state[kStateFrequencyIndex] = static_cast<std::uint32_t>(frequency);
    state[kStateChannelModeIndex] = static_cast<std::uint32_t>(channelMode & 0xFF);
    state[kStateJsBoundIndex] = static_cast<std::uint32_t>(jsBound);
    state[kStateEmphasisIndex] = static_cast<std::uint32_t>(emphasis & 0xFF);
    state[kStateSyncErrorIndex] = 0;
    state[kStateSyncCursorIndex] = 4;

    const int channelInfoStatus = mpadcd_ch_info_proc(state);
    if (channelInfoStatus < 0) {
      state[kStateSyncErrorIndex] = 0;
      state[kStateSyncCursorIndex] = 1;
      return channelInfoStatus;
    }

    mpadcd_check_crc(state);
    mpadcd_reset_dec_param(state);
    return 0;
  }

  /**
   * Address: 0x00B29D30 (_mpadcd_calc_frm_len)
   *
   * What it does:
   * Computes MPEG frame byte length from bitrate and sample-rate lanes.
   */
  int __cdecl mpadcd_calc_frm_len(std::uint32_t* state, unsigned int* outFrameLength)
  {
    const auto frequency = state[kStateFrequencyIndex];
    const auto bitRate = state[kStateBitRateIndex];
    if (frequency != 0 && bitRate != 0) {
      *outFrameLength = (144000u * bitRate) / frequency;
      return 0;
    }

    *outFrameLength = 0;
    return kMpaErrorMalformed;
  }

  /**
   * Address: 0x00B29CC0 (_mpadcd_SkipToNextFrm)
   *
   * What it does:
   * Advances stream cursor to next sync byte candidate.
   */
  int __cdecl mpadcd_SkipToNextFrm(std::uint32_t* state)
  {
    auto syncCursor = state[kStateSyncCursorIndex];
    const auto dataEnd = state[kStateSyncErrorIndex - 1]; // +0x6D0
    unsigned int frameLength = 0;

    if (mpadcd_calc_frm_len(state, &frameLength) == 0 && frameLength != 0) {
      if (syncCursor >= frameLength) {
        syncCursor = frameLength;
      }
    }

    const auto* const sourceBytes = reinterpret_cast<const std::uint8_t*>(state);
    unsigned int scanCursor = syncCursor;
    while (scanCursor < dataEnd) {
      if (sourceBytes[scanCursor + 12] == 0xFF) {
        break;
      }
      ++scanCursor;
    }

    state[kStateSyncCursorIndex] = scanCursor;
    state[kStateSyncErrorIndex] = 0;
    return 0;
  }

  /**
   * Address: 0x00B29D80 (_mpadcd_DequantizeSmpl)
   *
   * What it does:
   * Converts quantized sample lanes into dequantized floating-point coefficients.
   */
  int __cdecl mpadcd_DequantizeSmpl(std::uint32_t* state)
  {
    if (state[kStateChannelCountIndex] == 0) {
      return 0;
    }

    auto* const floatState = reinterpret_cast<float*>(state);
    std::int32_t channelTripletBase = 0;
    std::int32_t scaleFactorBase =
      32 * static_cast<std::int32_t>(state[kStateSynthesisScaleCursorIndex] >> 2);
    std::int32_t channelsRemaining =
      static_cast<std::int32_t>(state[kStateChannelCountIndex]);
    auto* bitAllocLane = state + kStateBitAllocBaseIndex;

    do {
      std::uint32_t tripletIndex = 0;
      do {
        auto* groupedTableLane = state + kStateDecodeTableGroupedBaseIndex;
        auto* bitAllocReadLane = bitAllocLane;

        for (std::uint32_t subband = 0; subband < 32; ++subband) {
          const auto bitAlloc = static_cast<std::int32_t>(*bitAllocReadLane);
          if (bitAlloc != 0) {
            const auto quantBits =
              reinterpret_cast<const std::int32_t*>(groupedTableLane[-64])[bitAlloc];
            const auto quantClass =
              reinterpret_cast<const std::int32_t*>(*groupedTableLane)[bitAlloc];
            const auto scalefactor =
              static_cast<std::int32_t>(state[subband + kStateScaleFactorBaseIndex + scaleFactorBase]);

            const auto sampleIndex =
              static_cast<std::int32_t>(
                subband + kStateQuantizedSampleBaseIndex + 32 * (tripletIndex + channelTripletBase)
              );
            const auto sampleCode = static_cast<std::int32_t>(state[sampleIndex]);
            const auto signBit = 1 << (quantBits - 1);
            const auto sampleMagnitude = sampleCode & (signBit - 1);
            const auto signBias = ((sampleCode & signBit) != 0) ? 0.0f : -1.0f;

            floatState[sampleIndex + 192] =
              (static_cast<float>(sampleMagnitude) * mpadcd_division_table[quantBits] + signBias +
               mpadcd_dequantize_table_d[quantClass]) *
              mpadcd_dequantize_denormze_table[64 * quantClass + scalefactor];
          }

          ++groupedTableLane;
          ++bitAllocReadLane;
        }

        ++tripletIndex;
      } while (tripletIndex < 3);

      bitAllocLane += 32;
      channelTripletBase += 3;
      scaleFactorBase += 96;
      --channelsRemaining;
    } while (channelsRemaining != 0);

    return 0;
  }

  /**
   * Address: 0x00B29F00 (_mpadcd_GetPcmSmpl)
   *
   * What it does:
   * Runs polyphase synthesis over dequantized lanes and emits PCM16 samples.
   */
  int __cdecl mpadcd_GetPcmSmpl(std::uint32_t* state)
  {
    unsigned int synthesisOffsetBytes = 0;
    unsigned int synthesisOffsetDwords = 0;
    auto* outputCursor =
      reinterpret_cast<std::uint16_t*>(reinterpret_cast<std::uint8_t*>(state) + kStatePcmOutputBytesOffset);
    const auto channelCount = state[kStateChannelCountIndex];
    unsigned int channelStrideWords = channelCount << 6;
    std::uintptr_t outputByteCursor =
      reinterpret_cast<std::uintptr_t>(reinterpret_cast<std::uint8_t*>(state) + kStatePcmOutputBytesOffset);

    do {
      int channelBase = 0;
      int channelIndex = 0;

      if (channelCount != 0) {
        auto* synthesisInput = reinterpret_cast<float*>(
          reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisInputBytesOffset + synthesisOffsetBytes
        );
        auto* channelOutputCursor = outputCursor;
        auto* channelInputBase = synthesisInput;
        std::intptr_t filterSeedBias = -reinterpret_cast<std::intptr_t>(synthesisInput);

        while (true) {
          std::uint32_t ringCursor = state[kStateSynthesisRingCursorBaseIndex + channelIndex];
          auto* destLaneA = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisOutputBytesOffset + 4 * (channelBase + ringCursor)
          );
          auto* destLaneB = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisOutputMirrorBytesOffset + 4 * (channelBase + ringCursor)
          );

          std::uint32_t tapBase = 0;
          auto* seedCursor = reinterpret_cast<std::uint8_t*>(mpadcd_synthesis_polyphase_seed_table) + filterSeedBias;
          do {
            double accum =
              static_cast<double>(mpadcd_synthesis_polyphase_seed_table[tapBase]) * static_cast<double>(*synthesisInput);

            auto* laneCursor = synthesisInput + 1;
            int remaining = 31;
            do {
              accum += static_cast<double>(*laneCursor) *
                       static_cast<double>(*reinterpret_cast<float*>(seedCursor + reinterpret_cast<std::intptr_t>(laneCursor)));
              ++laneCursor;
              --remaining;
            } while (remaining != 0);

            *destLaneA++ = static_cast<float>(accum);
            *destLaneB-- = static_cast<float>(-accum);
            tapBase += 32;
            seedCursor += 128;
          } while (tapBase < 512);

          auto* filterCursor =
            reinterpret_cast<std::uint8_t*>(mpadcd_synthesis_filter_table) + filterSeedBias;
          std::uint32_t upperTapBase = 1056;
          auto* upperLaneA = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisOutputUpperBytesOffset + 4 * (channelBase + ringCursor)
          );
          auto* upperLaneB = reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisCopyBytesOffset + 4 * (channelBase + ringCursor)
          );

          do {
            double accum =
              static_cast<double>(mpadcd_synthesis_polyphase_seed_table[upperTapBase]) *
              static_cast<double>(*channelInputBase);

            auto* laneCursor = channelInputBase + 1;
            int remaining = 31;
            do {
              accum += static_cast<double>(*laneCursor) *
                       static_cast<double>(*reinterpret_cast<float*>(filterCursor + reinterpret_cast<std::intptr_t>(laneCursor)));
              ++laneCursor;
              --remaining;
            } while (remaining != 0);

            *upperLaneA++ = static_cast<float>(accum);
            *upperLaneB-- = static_cast<float>(accum);
            upperTapBase += 32;
            filterCursor += 128;
          } while (upperTapBase < 1536);

          double sum = static_cast<double>(*channelInputBase);
          for (unsigned int lane = 1; lane < 32; ++lane) {
            sum += static_cast<double>(channelInputBase[lane]);
          }
          *reinterpret_cast<float*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisNegatedSumBytesOffset + 4 * (channelBase + ringCursor)
          ) = static_cast<float>(-sum);
          *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisOutputBytesOffset + 4 * (channelBase + ringCursor + 16)
          ) = 0;

          std::uint32_t ringStep = ringCursor;
          for (unsigned int windowLane = 448; windowLane < 480; ++windowLane) {
            const auto laneA = (ringStep + 96u) & 0x3FFu;
            const auto laneB = (laneA + 32u) & 0x3FFu;
            const auto laneC = (laneB + 96u) & 0x3FFu;
            const auto laneD = (laneC + 32u) & 0x3FFu;
            const auto laneE = (laneD + 96u) & 0x3FFu;
            const auto laneF = (laneE + 32u) & 0x3FFu;
            const auto laneG = (laneF + 96u) & 0x3FFu;
            const auto laneH = (laneG + 32u) & 0x3FFu;
            const auto laneI = (laneH + 96u) & 0x3FFu;
            const auto laneJ = (laneI + 32u) & 0x3FFu;
            const auto laneK = (laneJ + 96u) & 0x3FFu;
            const auto laneL = (laneK + 32u) & 0x3FFu;
            const auto laneM = (laneL + 96u) & 0x3FFu;
            const auto laneN = (laneM + 32u) & 0x3FFu;
            const auto laneO = (laneN + 96u) & 0x3FFu;
            const auto laneP = (laneO + 32u) & 0x3FFu;
            const auto laneQ = (laneP + 96u) & 0x3FFu;

            const auto fetch = [&](std::uint32_t lane) -> float {
              return *reinterpret_cast<float*>(
                reinterpret_cast<std::uint8_t*>(state) + kStateSynthesisOutputBytesOffset +
                4 * (channelBase + lane)
              );
            };

            double sample =
              static_cast<double>(fetch(ringStep)) * mpadcd_synthesis_window_table[windowLane - 448] +
              static_cast<double>(fetch(laneA)) * mpadcd_synthesis_window_table[windowLane - 416] +
              static_cast<double>(fetch(laneB)) * mpadcd_synthesis_window_table[windowLane - 384] +
              static_cast<double>(fetch(laneC)) * mpadcd_synthesis_window_table[windowLane - 352] +
              static_cast<double>(fetch(laneD)) * mpadcd_synthesis_window_table[windowLane - 320] +
              static_cast<double>(fetch(laneE)) * mpadcd_synthesis_window_table[windowLane - 288] +
              static_cast<double>(fetch(laneF)) * mpadcd_synthesis_window_table[windowLane - 256] +
              static_cast<double>(fetch(laneG)) * mpadcd_synthesis_window_table[windowLane - 224] +
              static_cast<double>(fetch(laneH)) * mpadcd_synthesis_window_table[windowLane - 192] +
              static_cast<double>(fetch(laneI)) * mpadcd_synthesis_window_table[windowLane - 160] +
              static_cast<double>(fetch(laneJ)) * mpadcd_synthesis_window_table[windowLane - 128] +
              static_cast<double>(fetch(laneK)) * mpadcd_synthesis_window_table[windowLane - 96] +
              static_cast<double>(fetch(laneL)) * mpadcd_synthesis_window_table[windowLane - 64] +
              static_cast<double>(fetch(laneM)) * mpadcd_synthesis_window_table[windowLane - 32] +
              static_cast<double>(fetch(laneN)) * mpadcd_synthesis_window_table[windowLane] +
              static_cast<double>(fetch(laneQ)) * mpadcd_synthesis_window_tail_table[windowLane];

            const double scaled = sample * 32768.0;
            const double rounded = scaled + ((scaled < 0.0) ? -0.5 : 0.5);
            int pcmValue = static_cast<int>(rounded);
            if (pcmValue > 0x7FFF) {
              pcmValue = 0x7FFF;
            } else if (pcmValue < -32768) {
              pcmValue = -32768;
            }

            *channelOutputCursor = static_cast<std::uint16_t>(pcmValue);
            ringStep += 1;
            channelOutputCursor += channelCount;
          }

          if (ringCursor < 0x40) {
            state[kStateSynthesisRingCursorBaseIndex + channelIndex] = ringCursor + 1024;
          }
          state[kStateSynthesisRingCursorBaseIndex + channelIndex] -= 64;

          ++channelIndex;
          channelBase += 1024;
          filterSeedBias -= 384;
          channelInputBase += 96;
          ++outputCursor;
          if (channelIndex >= static_cast<int>(channelCount)) {
            break;
          }
          synthesisInput = channelInputBase;
        }

        channelStrideWords = channelCount << 6;
      }

      synthesisOffsetBytes += 128;
      synthesisOffsetDwords += 32;
      outputByteCursor += channelStrideWords * 2;
      outputCursor = reinterpret_cast<std::uint16_t*>(outputByteCursor);
    } while (synthesisOffsetDwords < 0x180u);

    return 0;
  }
}
