#include <cstddef>
#include <cstdint>

extern "C"
{
  extern int __cdecl mpabsr_ReadBitStm(
    std::uint8_t* stateBytes,
    int bitCount,
    std::uint8_t** outBits
  );

  extern std::int32_t mpadcd_5bit_mixed_smpl1[];
  extern std::int32_t mpadcd_5bit_mixed_smpl2[];
  extern std::int32_t mpadcd_5bit_mixed_smpl3[];
  extern std::int32_t mpadcd_7bit_mixed_smpl1[];
  extern std::int32_t mpadcd_7bit_mixed_smpl2[];
  extern std::int32_t mpadcd_7bit_mixed_smpl3[];
  extern std::int32_t mpadcd_10bit_mixed_smpl1[];
  extern std::int32_t mpadcd_10bit_mixed_smpl2[];
  extern std::int32_t mpadcd_10bit_mixed_smpl3[];

  extern std::int32_t mpadcd_bits_type1_2bit[];
  extern std::int32_t mpadcd_bits_type1_3bit[];
  extern std::int32_t mpadcd_bits_type1_4bit_high[];
  extern std::int32_t mpadcd_bits_type1_4bit_low[];
  extern std::int32_t mpadcd_group_type1_high[];
  extern std::int32_t mpadcd_quant_type1_3bit[];
  extern std::int32_t mpadcd_quant_type1_4bit_high[];
  extern std::int32_t mpadcd_quant_type1_4bit_low[];
  extern std::int32_t alloc_len_08sb[];
  extern std::int32_t alloc_len_12sb[];
  extern std::int32_t alloc_len_27sb[];
  extern std::int32_t alloc_len_30sb[];

  namespace
  {
    constexpr std::size_t kSubbandCount = 32;
    constexpr std::size_t kChannelStride = 32;
    constexpr std::size_t kSampleChannelStride = 96;

    constexpr std::size_t kBitRateIndex = 441; // +0x6E4
    constexpr std::size_t kSampleRateIndex = 442; // +0x6E8
    constexpr std::size_t kChannelCountIndex = 445; // +0x6F4
    constexpr std::size_t kJsBoundIndex = 446; // +0x6F8
    constexpr std::size_t kAllocTypeIndex = 449; // +0x704
    constexpr std::size_t kAllocLengthTablePtrIndex = 450; // +0x708

    constexpr std::size_t kBitAllocBase = 451; // +0x70C
    constexpr std::size_t kScfSelectBase = 515; // +0x80C
    constexpr std::size_t kScfValue0Base = 579; // +0x90C
    constexpr std::size_t kScfValue1Base = 611; // +0x98C
    constexpr std::size_t kScfValue2Base = 643; // +0xA0C

    constexpr std::size_t kDecodeDirectTableBase = 771; // +0xC0C
    constexpr std::size_t kDecodeGroupedBitsTableBase = 803; // +0xC8C
    constexpr std::size_t kDecodeGroupedTableBase = 835; // +0xD0C

    constexpr std::size_t kSampleValue0Base = 867; // +0xD8C
    constexpr std::size_t kSampleValue1Base = 899; // +0xE0C
    constexpr std::size_t kSampleValue2Base = 931; // +0xE8C

    [[nodiscard]] inline std::size_t MatrixIndex(
      const std::size_t base,
      const std::size_t subbandIndex,
      const std::size_t channelIndex
    )
    {
      return base + subbandIndex + channelIndex * kChannelStride;
    }

    [[nodiscard]] inline std::size_t SampleIndex(
      const std::size_t base,
      const std::size_t subbandIndex,
      const std::size_t channelIndex
    )
    {
      return base + subbandIndex + channelIndex * kSampleChannelStride;
    }

    [[nodiscard]] inline std::uint32_t PointerToLane(const void* pointerValue)
    {
      return static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(pointerValue)
      );
    }

    [[nodiscard]] inline const std::int32_t* LaneToConstIntPointer(
      const std::uint32_t laneValue
    )
    {
      return reinterpret_cast<const std::int32_t*>(
        static_cast<std::uintptr_t>(laneValue)
      );
    }

    inline int ReadBitField(
      std::uint32_t* decoderState,
      const int bitCount,
      int* outValue
    )
    {
      std::uint8_t* rawBitValue = nullptr;
      const int status = mpabsr_ReadBitStm(
        reinterpret_cast<std::uint8_t*>(decoderState),
        bitCount,
        &rawBitValue
      );

      *outValue = static_cast<int>(reinterpret_cast<std::uintptr_t>(rawBitValue));
      return status;
    }

    inline void DecodeGroupedSampleTriplet(
      const int groupedBitCount,
      const int packedValue,
      int* outValue0,
      int* outValue1,
      int* outValue2
    )
    {
      if (groupedBitCount == 5) {
        *outValue0 = mpadcd_5bit_mixed_smpl1[packedValue];
        *outValue1 = mpadcd_5bit_mixed_smpl2[packedValue];
        *outValue2 = mpadcd_5bit_mixed_smpl3[packedValue];
        return;
      }

      if (groupedBitCount == 7) {
        *outValue0 = mpadcd_7bit_mixed_smpl1[packedValue];
        *outValue1 = mpadcd_7bit_mixed_smpl2[packedValue];
        *outValue2 = mpadcd_7bit_mixed_smpl3[packedValue];
        return;
      }

      *outValue0 = mpadcd_10bit_mixed_smpl1[packedValue];
      *outValue1 = mpadcd_10bit_mixed_smpl2[packedValue];
      *outValue2 = mpadcd_10bit_mixed_smpl3[packedValue];
    }
  } // namespace

  /**
   * Address: 0x00B2A930 (_mpadcd_get_alloc_type)
   *
   * What it does:
   * Selects one bit-allocation profile from sample-rate and bitrate lanes.
   */
  int __cdecl mpadcd_get_alloc_type(std::uint32_t* decoderState)
  {
    const auto sampleRate = static_cast<int>(decoderState[kSampleRateIndex]);
    const auto channelCount = decoderState[kChannelCountIndex];
    const auto bitratePerChannel = decoderState[kBitRateIndex] / channelCount;

    if (sampleRate == 44100) {
      if (bitratePerChannel <= 0x30) {
        decoderState[kAllocTypeIndex] = 8;
        return 0;
      }
    } else {
      if (sampleRate == 48000) {
        decoderState[kAllocTypeIndex] = (bitratePerChannel > 0x30) ? 27u : 8u;
        return 0;
      }

      if (bitratePerChannel <= 0x30) {
        decoderState[kAllocTypeIndex] = 12;
        return 0;
      }
    }

    decoderState[kAllocTypeIndex] = (bitratePerChannel > 0x50) ? 30u : 27u;
    return 0;
  }

  /**
   * Address: 0x00B2A9C0 (_mpadcd_load_dec_table)
   *
   * What it does:
   * Loads allocation decode-table lanes for the active profile.
   */
  int __cdecl mpadcd_load_dec_table(std::uint32_t* decoderState)
  {
    auto setDecodeTables = [&](const std::size_t subbandIndex, const std::int32_t* directTable,
                               const std::int32_t* groupedBitsTable, const std::int32_t* groupedTable) {
      decoderState[kDecodeDirectTableBase + subbandIndex] = PointerToLane(directTable);
      decoderState[kDecodeGroupedBitsTableBase + subbandIndex] =
        PointerToLane(groupedBitsTable);
      decoderState[kDecodeGroupedTableBase + subbandIndex] = PointerToLane(groupedTable);
    };

    if (decoderState[kAllocTypeIndex] < 0x1B) {
      for (std::size_t subbandIndex = 0; subbandIndex < 2; ++subbandIndex) {
        setDecodeTables(
          subbandIndex,
          mpadcd_bits_type1_3bit,
          mpadcd_quant_type1_3bit + 16,
          mpadcd_bits_type1_3bit + 16
        );
      }

      for (std::size_t subbandIndex = 2; subbandIndex < kSubbandCount; ++subbandIndex) {
        setDecodeTables(
          subbandIndex,
          mpadcd_quant_type1_3bit,
          mpadcd_quant_type1_3bit + 16,
          mpadcd_bits_type1_2bit
        );
      }

      return 0;
    }

    for (std::size_t subbandIndex = 0; subbandIndex < 3; ++subbandIndex) {
      setDecodeTables(
        subbandIndex,
        mpadcd_bits_type1_4bit_high,
        mpadcd_bits_type1_4bit_high + 16,
        mpadcd_group_type1_high
      );
    }

    for (std::size_t subbandIndex = 3; subbandIndex < 11; ++subbandIndex) {
      setDecodeTables(
        subbandIndex,
        mpadcd_group_type1_high + 16,
        mpadcd_quant_type1_4bit_low,
        mpadcd_quant_type1_4bit_high
      );
    }

    for (std::size_t subbandIndex = 11; subbandIndex < 23; ++subbandIndex) {
      setDecodeTables(
        subbandIndex,
        mpadcd_quant_type1_4bit_high + 16,
        mpadcd_quant_type1_4bit_low,
        mpadcd_bits_type1_4bit_low
      );
    }

    for (std::size_t subbandIndex = 23; subbandIndex < kSubbandCount; ++subbandIndex) {
      setDecodeTables(
        subbandIndex,
        mpadcd_bits_type1_4bit_low + 16,
        mpadcd_quant_type1_4bit_low,
        mpadcd_quant_type1_4bit_low + 16
      );
    }

    return 0;
  }

  /**
   * Address: 0x00B2AAC0 (_mpadcd_get_alloc_len)
   *
   * What it does:
   * Selects per-subband allocation bit-length table for active profile.
   */
  int __cdecl mpadcd_get_alloc_len(std::uint32_t* decoderState)
  {
    const auto allocType = decoderState[kAllocTypeIndex];
    if (allocType == 12) {
      decoderState[kAllocLengthTablePtrIndex] = PointerToLane(alloc_len_12sb);
      return 0;
    }

    if (allocType == 27) {
      decoderState[kAllocLengthTablePtrIndex] = PointerToLane(alloc_len_27sb);
      return 0;
    }

    if (allocType == 30) {
      decoderState[kAllocLengthTablePtrIndex] = PointerToLane(alloc_len_30sb);
      return 0;
    }

    decoderState[kAllocLengthTablePtrIndex] = PointerToLane(alloc_len_08sb);
    return 0;
  }

  /**
   * Address: 0x00B2AB20 (_mpadcd_get_bit_alloc)
   *
   * What it does:
   * Reads per-subband bit-allocation lanes from packed bitstream.
   */
  int __cdecl mpadcd_get_bit_alloc(std::uint32_t* decoderState)
  {
    const auto channels = static_cast<int>(decoderState[kChannelCountIndex]);
    const auto bound = static_cast<unsigned int>(decoderState[kJsBoundIndex]);
    const auto* allocLengthTable =
      LaneToConstIntPointer(decoderState[kAllocLengthTablePtrIndex]);

    if (bound > 0) {
      for (unsigned int subbandIndex = 0; subbandIndex < bound; ++subbandIndex) {
        for (int channelIndex = 0; channelIndex < channels; ++channelIndex) {
          const auto allocLength = allocLengthTable[
            subbandIndex + static_cast<unsigned int>(channelIndex) * kChannelStride
          ];
          if (allocLength == 0) {
            continue;
          }

          int allocValue = 0;
          ReadBitField(decoderState, allocLength, &allocValue);
          decoderState[MatrixIndex(kBitAllocBase, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(allocValue);
        }
      }
    }

    if (bound < kSubbandCount) {
      for (unsigned int subbandIndex = bound; subbandIndex < kSubbandCount; ++subbandIndex) {
        const auto allocLength = allocLengthTable[subbandIndex];
        if (allocLength == 0) {
          continue;
        }

        int allocValue = 0;
        ReadBitField(decoderState, allocLength, &allocValue);
        decoderState[MatrixIndex(kBitAllocBase, subbandIndex, 0)] =
          static_cast<std::uint32_t>(allocValue);
        decoderState[MatrixIndex(kBitAllocBase, subbandIndex, 1)] =
          static_cast<std::uint32_t>(allocValue);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2A900 (_mpadcd_GetBitAllocInfo)
   *
   * What it does:
   * Runs allocation profile/table/length/read pipeline for current frame.
   */
  int __cdecl mpadcd_GetBitAllocInfo(std::uint32_t* decoderState)
  {
    mpadcd_get_alloc_type(decoderState);
    mpadcd_load_dec_table(decoderState);
    mpadcd_get_alloc_len(decoderState);
    mpadcd_get_bit_alloc(decoderState);
    return 0;
  }

  /**
   * Address: 0x00B2A720 (_mpadcd_get_scf_slct_info)
   *
   * What it does:
   * Reads scale-factor selection-info lanes for allocated subbands.
   */
  int __cdecl mpadcd_get_scf_slct_info(std::uint32_t* decoderState)
  {
    const auto channels = static_cast<int>(decoderState[kChannelCountIndex]);

    for (std::size_t subbandIndex = 0; subbandIndex < kSubbandCount; ++subbandIndex) {
      for (int channelIndex = 0; channelIndex < channels; ++channelIndex) {
        if (decoderState[MatrixIndex(kBitAllocBase, subbandIndex, channelIndex)] == 0) {
          continue;
        }

        int selectValue = 0;
        ReadBitField(decoderState, 2, &selectValue);
        decoderState[MatrixIndex(kScfSelectBase, subbandIndex, channelIndex)] =
          static_cast<std::uint32_t>(selectValue);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2A7A0 (_mpadcd_get_scf_info)
   *
   * What it does:
   * Reads scale-factor payload triplets for allocated subbands.
   */
  int __cdecl mpadcd_get_scf_info(std::uint32_t* decoderState)
  {
    const auto channels = static_cast<int>(decoderState[kChannelCountIndex]);

    for (std::size_t subbandIndex = 0; subbandIndex < kSubbandCount; ++subbandIndex) {
      for (int channelIndex = 0; channelIndex < channels; ++channelIndex) {
        if (decoderState[MatrixIndex(kBitAllocBase, subbandIndex, channelIndex)] == 0) {
          continue;
        }

        const auto selectValue = static_cast<int>(
          decoderState[MatrixIndex(kScfSelectBase, subbandIndex, channelIndex)]
        );

        int value0 = 0;
        int value1 = 0;
        int value2 = 0;

        if (selectValue == 0) {
          ReadBitField(decoderState, 6, &value0);
          ReadBitField(decoderState, 6, &value1);
          ReadBitField(decoderState, 6, &value2);
        } else if (selectValue == 1) {
          ReadBitField(decoderState, 6, &value0);
          value1 = value0;
          ReadBitField(decoderState, 6, &value2);
        } else if (selectValue == 2) {
          ReadBitField(decoderState, 6, &value0);
          value1 = value0;
          value2 = value0;
        } else {
          ReadBitField(decoderState, 6, &value0);
          ReadBitField(decoderState, 6, &value1);
          value2 = value1;
        }

        decoderState[MatrixIndex(kScfValue0Base, subbandIndex, channelIndex)] =
          static_cast<std::uint32_t>(value0);
        decoderState[MatrixIndex(kScfValue1Base, subbandIndex, channelIndex)] =
          static_cast<std::uint32_t>(value1);
        decoderState[MatrixIndex(kScfValue2Base, subbandIndex, channelIndex)] =
          static_cast<std::uint32_t>(value2);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2A700 (_mpadcd_GetScfInfo)
   *
   * What it does:
   * Runs scale-factor select+payload decode pipeline.
   */
  int __cdecl mpadcd_GetScfInfo(std::uint32_t* decoderState)
  {
    mpadcd_get_scf_slct_info(decoderState);
    mpadcd_get_scf_info(decoderState);
    return 0;
  }

  /**
   * Address: 0x00B2A400 (_mpadcd_GetSmpl)
   *
   * What it does:
   * Reads and dequantizes sample triplets from bitstream into runtime lanes.
   */
  int __cdecl mpadcd_GetSmpl(std::uint32_t* decoderState)
  {
    const auto channels = static_cast<int>(decoderState[kChannelCountIndex]);
    const auto bound = static_cast<unsigned int>(decoderState[kJsBoundIndex]);

    if (bound > 0) {
      for (unsigned int subbandIndex = 0; subbandIndex < bound; ++subbandIndex) {
        const auto* directDecodeTable =
          LaneToConstIntPointer(decoderState[kDecodeDirectTableBase + subbandIndex]);
        const auto* groupedBitsTable = LaneToConstIntPointer(
          decoderState[kDecodeGroupedBitsTableBase + subbandIndex]
        );

        for (int channelIndex = 0; channelIndex < channels; ++channelIndex) {
          const int bitAlloc = static_cast<int>(
            decoderState[MatrixIndex(kBitAllocBase, subbandIndex, channelIndex)]
          );
          if (bitAlloc == 0) {
            continue;
          }

          int sample0 = 0;
          int sample1 = 0;
          int sample2 = 0;

          const int groupedBitCount = groupedBitsTable[bitAlloc];
          if (groupedBitCount != 0) {
            int packedSample = 0;
            ReadBitField(decoderState, groupedBitCount, &packedSample);
            DecodeGroupedSampleTriplet(
              groupedBitCount,
              packedSample,
              &sample0,
              &sample1,
              &sample2
            );
          } else {
            const int directBitCount = directDecodeTable[bitAlloc];
            ReadBitField(decoderState, directBitCount, &sample0);
            ReadBitField(decoderState, directBitCount, &sample1);
            ReadBitField(decoderState, directBitCount, &sample2);
          }

          decoderState[SampleIndex(kSampleValue0Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample0);
          decoderState[SampleIndex(kSampleValue1Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample1);
          decoderState[SampleIndex(kSampleValue2Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample2);
        }
      }
    }

    if (bound < kSubbandCount) {
      for (unsigned int subbandIndex = bound; subbandIndex < kSubbandCount; ++subbandIndex) {
        const auto* directDecodeTable =
          LaneToConstIntPointer(decoderState[kDecodeDirectTableBase + subbandIndex]);
        const auto* groupedBitsTable = LaneToConstIntPointer(
          decoderState[kDecodeGroupedBitsTableBase + subbandIndex]
        );

        const int bitAlloc = static_cast<int>(
          decoderState[MatrixIndex(kBitAllocBase, subbandIndex, 0)]
        );
        if (bitAlloc == 0) {
          continue;
        }

        int sample0 = 0;
        int sample1 = 0;
        int sample2 = 0;

        const int groupedBitCount = groupedBitsTable[bitAlloc];
        if (groupedBitCount != 0) {
          int packedSample = 0;
          ReadBitField(decoderState, groupedBitCount, &packedSample);
          DecodeGroupedSampleTriplet(
            groupedBitCount,
            packedSample,
            &sample0,
            &sample1,
            &sample2
          );
        } else {
          const int directBitCount = directDecodeTable[bitAlloc];
          ReadBitField(decoderState, directBitCount, &sample0);
          ReadBitField(decoderState, directBitCount, &sample1);
          ReadBitField(decoderState, directBitCount, &sample2);
        }

        for (int channelIndex = 0; channelIndex < 2; ++channelIndex) {
          decoderState[SampleIndex(kSampleValue0Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample0);
          decoderState[SampleIndex(kSampleValue1Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample1);
          decoderState[SampleIndex(kSampleValue2Base, subbandIndex, channelIndex)] =
            static_cast<std::uint32_t>(sample2);
        }
      }
    }

    return 0;
  }
}
