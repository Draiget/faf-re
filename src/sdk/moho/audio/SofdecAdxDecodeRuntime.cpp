#include <cstdint>
#include <cstring>

extern "C"
{
  extern std::int32_t adx_decode_output_mono_flag;
  extern std::int32_t AdxQtbl[];
  extern float AdxQtblFloat0[];
  extern float AdxQtblFloat1[];

  void mpabdr_GetBitVal8(std::uint8_t sourceByte, int bitOffset, int bitCount, int* outValue);
  void mpabdr_GetBitVal16(const std::uint8_t* sourceBytes, int bitOffset, int bitCount, int* outValue);
  void mpabdr_GetBitVal32(const std::uint8_t* sourceBytes, int bitOffset, int bitCount, std::uint32_t* outValue);

  namespace
  {
    [[nodiscard]] inline std::int32_t SaturateS16(const std::int32_t value)
    {
      if (value > 0x7FFF) {
        return 0x7FFF;
      }
      if (value < -32768) {
        return -32768;
      }
      return value;
    }
  }

  /**
   * Address: 0x00B2C4D0 (_mpabsr_ReadBitStm)
   *
   * What it does:
   * Reads one bit-range from MPA bitstream state lanes and advances cursor.
   */
  int __cdecl mpabsr_ReadBitStm(std::uint8_t* stateBytes, int bitCount, std::uint8_t** outBits)
  {
    auto* const stateLanes = reinterpret_cast<std::uint32_t*>(stateBytes);
    *outBits = nullptr;

    const std::int32_t bitOffset = static_cast<std::int32_t>(stateLanes[437]);
    const std::int32_t byteOffset = static_cast<std::int32_t>(stateLanes[438]);
    const std::int32_t combinedBits = bitOffset + bitCount;
    const std::uint32_t byteAdvance = static_cast<std::uint32_t>(combinedBits) >> 3;

    if (byteOffset + static_cast<std::int32_t>(byteAdvance) > static_cast<std::int32_t>(stateLanes[436])) {
      return -21;
    }

    std::uint8_t* extractedBits = nullptr;
    if (byteAdvance != 0u) {
      if (byteAdvance == 1u) {
        int value16 = 0;
        mpabdr_GetBitVal16(&stateBytes[byteOffset + 12], bitOffset, bitCount, &value16);
        extractedBits = reinterpret_cast<std::uint8_t*>(
          static_cast<std::uintptr_t>(static_cast<std::uint16_t>(value16))
        );
      } else {
        std::uint32_t value32 = 0;
        mpabdr_GetBitVal32(&stateBytes[byteOffset + 12], bitOffset, bitCount, &value32);
        extractedBits = reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(value32));
      }
    } else {
      int value8 = 0;
      mpabdr_GetBitVal8(stateBytes[byteOffset + 12], bitOffset, bitCount, &value8);
      extractedBits = reinterpret_cast<std::uint8_t*>(
        static_cast<std::uintptr_t>(static_cast<std::uint8_t>(value8))
      );
    }

    stateLanes[437] = static_cast<std::uint32_t>(combinedBits & 7);
    stateLanes[438] = static_cast<std::uint32_t>(byteOffset + static_cast<std::int32_t>(byteAdvance));
    *outBits = extractedBits;
    return 0;
  }

  /**
   * Address: 0x00B2BC40 (_ADX_DecodeMono4)
   *
   * What it does:
   * Decodes ADX mono 4-bit blocks into PCM output with predictor/state update.
   */
  int __cdecl ADX_DecodeMono4(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outSamples,
    std::int16_t* history,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  )
  {
    auto* const historyLanes = reinterpret_cast<std::int16_t*>(history);
    std::int32_t prev0 = historyLanes[0];
    std::int32_t prev1 = historyLanes[1];
    int processedBlocks = 0;

    if (blockCount > 0) {
      while (*sourceBytes >= 0) {
        std::int32_t nibblePairsRemaining = 16;

        const std::uint16_t header =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[0])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[1])
          );
        const std::int16_t scale =
          static_cast<std::int16_t>(
            (static_cast<std::uint16_t>(header ^ *keyState) & 0x1FFFu)
          );

        *keyState = static_cast<std::uint16_t>((keyAdd + keyMul * (*keyState)) & 0x7FFF);

        char* nibblePairCursor = sourceBytes + 2;
        const std::int32_t decodeScale = static_cast<std::int16_t>(scale + 1);
        std::int32_t currentCoef0 = coef0;

        while (true) {
          const std::uint8_t nibblePair = static_cast<std::uint8_t>(*nibblePairCursor);
          ++nibblePairCursor;

          std::int32_t sample0 =
            decodeScale * (static_cast<std::int8_t>(nibblePair) >> 4) +
            ((prev1 * coef1 + prev0 * currentCoef0) >> 12);
          sample0 = SaturateS16(sample0);

          *outSamples = static_cast<std::uint16_t>(sample0);

          std::int32_t sample1 =
            decodeScale * AdxQtbl[nibblePair & 0x0Fu] +
            ((prev0 * coef1 + sample0 * coef0) >> 12);
          sample1 = SaturateS16(sample1);

          outSamples[1] = static_cast<std::uint16_t>(sample1);
          outSamples += 2;

          prev1 = sample0;
          prev0 = sample1;

          if (--nibblePairsRemaining == 0) {
            break;
          }
        }

        ++processedBlocks;
        if (processedBlocks >= blockCount) {
          break;
        }

        sourceBytes = nibblePairCursor;
      }

      if (*sourceBytes < 0) {
        return processedBlocks;
      }
    }

    historyLanes[0] = static_cast<std::int16_t>(prev0);
    historyLanes[1] = static_cast<std::int16_t>(prev1);
    return blockCount;
  }

  /**
   * Address: 0x00B2BDE0 (_ADX_DecodeSte4AsMono)
   *
   * What it does:
   * Decodes stereo 4-bit ADX blocks but writes mixed-mono output lanes.
   */
  int __cdecl ADX_DecodeSte4AsMono(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  )
  {
    auto* const leftHistoryLanes = reinterpret_cast<std::int16_t*>(leftHistory);
    auto* const rightHistoryLanes = reinterpret_cast<std::int16_t*>(rightHistory);

    std::int32_t leftPrev0 = leftHistoryLanes[0];
    std::int32_t leftPrev1 = leftHistoryLanes[1];
    std::int32_t rightPrev0 = rightHistoryLanes[0];
    std::int32_t rightPrev1 = rightHistoryLanes[1];
    int processedHalfBlocks = 0;

    if (blockCount / 2 > 0) {
      while (true) {
        if (*sourceBytes < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t leftHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[0])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[1])
          );
        const std::int16_t leftScale =
          static_cast<std::int16_t>((leftHeader ^ *keyState) & 0x1FFFu);

        const std::int16_t keyA = static_cast<std::int16_t>((keyAdd + keyMul * (*keyState)) & 0x7FFF);
        *keyState = static_cast<std::uint16_t>(keyA);

        const std::uint16_t rightHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[18])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[19])
          );
        if (static_cast<std::int16_t>(rightHeader) < 0) {
          return 2 * processedHalfBlocks;
        }

        *keyState = static_cast<std::uint16_t>((keyAdd + keyMul * keyA) & 0x7FFF);

        char* leftNibbleCursor = sourceBytes + 2;
        const std::int32_t leftDecodeScale = static_cast<std::int16_t>(leftScale + 1);
        const std::int32_t rightDecodeScale =
          static_cast<std::int16_t>(((rightHeader ^ keyA) & 0x1FFFu) + 1);
        std::int32_t pairsRemaining = 16;

        while (true) {
          const std::uint8_t leftPair = static_cast<std::uint8_t>(*leftNibbleCursor);
          const std::uint8_t rightPair = static_cast<std::uint8_t>(leftNibbleCursor[18]);
          ++leftNibbleCursor;

          std::int32_t leftSample0 =
            leftDecodeScale * (static_cast<std::int8_t>(leftPair) >> 4) +
            ((leftPrev1 * coef1 + leftPrev0 * coef0) >> 12);
          leftSample0 = SaturateS16(leftSample0);

          std::int32_t rightSample0 =
            (static_cast<std::int8_t>(rightPair) >> 4) * rightDecodeScale +
            ((rightPrev1 * coef1 + rightPrev0 * coef0) >> 12);
          rightSample0 = SaturateS16(rightSample0);

          std::int32_t mixed0 = (7 * (leftSample0 + rightSample0)) / 10;
          mixed0 = SaturateS16(mixed0);
          *outLeftSamples = static_cast<std::uint16_t>(mixed0);
          *outRightSamples = static_cast<std::uint16_t>(mixed0);

          std::int32_t leftSample1 =
            leftDecodeScale * AdxQtbl[leftPair & 0x0Fu] +
            ((leftPrev0 * coef1 + leftSample0 * coef0) >> 12);
          leftSample1 = SaturateS16(leftSample1);

          std::int32_t rightSample1 =
            AdxQtbl[rightPair & 0x0Fu] * rightDecodeScale +
            ((rightPrev0 * coef1 + rightSample0 * coef0) >> 12);
          rightSample1 = SaturateS16(rightSample1);

          std::int32_t mixed1 = (7 * (leftSample1 + rightSample1)) / 10;
          mixed1 = SaturateS16(mixed1);

          outLeftSamples[1] = static_cast<std::uint16_t>(mixed1);
          outRightSamples[1] = static_cast<std::uint16_t>(mixed1);
          outLeftSamples += 2;
          outRightSamples += 2;

          leftPrev0 = leftSample1;
          leftPrev1 = leftSample0;
          rightPrev0 = rightSample1;
          rightPrev1 = rightSample0;

          if (--pairsRemaining == 0) {
            break;
          }
        }

        sourceBytes = leftNibbleCursor + 18;
        ++processedHalfBlocks;
        if (processedHalfBlocks >= blockCount / 2) {
          break;
        }
      }
    }

    leftHistoryLanes[0] = static_cast<std::int16_t>(leftPrev0);
    leftHistoryLanes[1] = static_cast<std::int16_t>(leftPrev1);
    rightHistoryLanes[0] = static_cast<std::int16_t>(rightPrev0);
    rightHistoryLanes[1] = static_cast<std::int16_t>(rightPrev1);
    return blockCount;
  }

  /**
   * Address: 0x00B2C170 (_ADX_DecodeSte4AsSte)
   *
   * What it does:
   * Decodes stereo 4-bit ADX blocks into discrete L/R PCM output lanes.
   */
  int __cdecl ADX_DecodeSte4AsSte(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  )
  {
    auto* const leftHistoryLanes = reinterpret_cast<std::int16_t*>(leftHistory);
    auto* const rightHistoryLanes = reinterpret_cast<std::int16_t*>(rightHistory);

    std::int32_t leftPrev0 = leftHistoryLanes[0];
    std::int32_t leftPrev1 = leftHistoryLanes[1];
    std::int32_t rightPrev0 = rightHistoryLanes[0];
    std::int32_t rightPrev1 = rightHistoryLanes[1];
    int processedHalfBlocks = 0;

    if (blockCount / 2 > 0) {
      while (true) {
        if (*sourceBytes < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t leftHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[0])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[1])
          );
        const std::int16_t leftScale =
          static_cast<std::int16_t>((leftHeader ^ *keyState) & 0x1FFFu);

        const std::int16_t keyA = static_cast<std::int16_t>((keyAdd + keyMul * (*keyState)) & 0x7FFF);
        *keyState = static_cast<std::uint16_t>(keyA);

        const std::uint16_t rightHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[18])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[19])
          );
        if (static_cast<std::int16_t>(rightHeader) < 0) {
          return 2 * processedHalfBlocks;
        }

        *keyState = static_cast<std::uint16_t>((keyAdd + keyMul * keyA) & 0x7FFF);

        char* leftNibbleCursor = sourceBytes + 2;
        const std::int32_t leftDecodeScale = static_cast<std::int16_t>(leftScale + 1);
        const std::int32_t rightDecodeScale =
          static_cast<std::int16_t>(((rightHeader ^ keyA) & 0x1FFFu) + 1);
        std::int32_t pairsRemaining = 16;

        while (true) {
          const std::uint8_t leftPair = static_cast<std::uint8_t>(*leftNibbleCursor);
          const std::uint8_t rightPair = static_cast<std::uint8_t>(leftNibbleCursor[18]);
          ++leftNibbleCursor;

          std::int32_t leftSample0 =
            leftDecodeScale * (static_cast<std::int8_t>(leftPair) >> 4) +
            ((leftPrev1 * coef1 + leftPrev0 * coef0) >> 12);
          leftSample0 = SaturateS16(leftSample0);

          std::int32_t rightSample0 =
            (static_cast<std::int8_t>(rightPair) >> 4) * rightDecodeScale +
            ((rightPrev1 * coef1 + rightPrev0 * coef0) >> 12);
          rightSample0 = SaturateS16(rightSample0);

          *outLeftSamples = static_cast<std::uint16_t>(leftSample0);
          *outRightSamples = static_cast<std::uint16_t>(rightSample0);

          std::int32_t leftSample1 =
            leftDecodeScale * AdxQtbl[leftPair & 0x0Fu] +
            ((leftPrev0 * coef1 + leftSample0 * coef0) >> 12);
          leftSample1 = SaturateS16(leftSample1);

          std::int32_t rightSample1 =
            AdxQtbl[rightPair & 0x0Fu] * rightDecodeScale +
            ((rightPrev0 * coef1 + rightSample0 * coef0) >> 12);
          rightSample1 = SaturateS16(rightSample1);

          outLeftSamples[1] = static_cast<std::uint16_t>(leftSample1);
          outRightSamples[1] = static_cast<std::uint16_t>(rightSample1);
          outLeftSamples += 2;
          outRightSamples += 2;

          leftPrev0 = leftSample1;
          leftPrev1 = leftSample0;
          rightPrev0 = rightSample1;
          rightPrev1 = rightSample0;

          if (--pairsRemaining == 0) {
            break;
          }
        }

        sourceBytes = leftNibbleCursor + 18;
        ++processedHalfBlocks;
        if (processedHalfBlocks >= blockCount / 2) {
          break;
        }
      }
    }

    leftHistoryLanes[0] = static_cast<std::int16_t>(leftPrev0);
    leftHistoryLanes[1] = static_cast<std::int16_t>(leftPrev1);
    rightHistoryLanes[0] = static_cast<std::int16_t>(rightPrev0);
    rightHistoryLanes[1] = static_cast<std::int16_t>(rightPrev1);
    return blockCount;
  }

  /**
   * Address: 0x00B2C470 (_ADX_DecodeSte4)
   *
   * What it does:
   * Dispatches ADX stereo 4-bit decode to mono/stereo output mode.
   */
  int __cdecl ADX_DecodeSte4(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    std::int16_t coef1,
    std::uint16_t* keyState,
    std::int16_t keyMul,
    std::int16_t keyAdd
  )
  {
    if (adx_decode_output_mono_flag != 0) {
      return ADX_DecodeSte4AsMono(
        sourceBytes,
        blockCount,
        outLeftSamples,
        leftHistory,
        outRightSamples,
        rightHistory,
        coef0,
        coef1,
        keyState,
        keyMul,
        keyAdd
      );
    }

    return ADX_DecodeSte4AsSte(
      sourceBytes,
      blockCount,
      outLeftSamples,
      leftHistory,
      outRightSamples,
      rightHistory,
      coef0,
      coef1,
      keyState,
      keyMul,
      keyAdd
    );
  }

  /**
   * Address: 0x00B2C5B0 (_ADX_DecodeMonoFloat)
   *
   * What it does:
   * Decodes ADX mono float-path blocks into PCM output lanes.
   */
  int __cdecl ADX_DecodeMonoFloat(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outSamples,
    std::int16_t* history,
    std::int16_t coef0,
    std::int16_t coef1
  )
  {
    auto* const historyLanes = reinterpret_cast<std::int16_t*>(history);

    float prev0 = static_cast<float>(historyLanes[0] << 16);
    float prev1 = static_cast<float>(historyLanes[1] << 16);
    int processedBlocks = 0;

    const float scaledCoef0 = static_cast<float>(16 * coef0) * 0.000015258789f;
    const float scaledCoef1 = static_cast<float>(16 * coef1) * 0.000015258789f;

    if (blockCount > 0) {
      while (true) {
        if (*sourceBytes < 0) {
          return processedBlocks;
        }

        const std::uint16_t header =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(sourceBytes[0])) << 8) |
            static_cast<std::uint8_t>(sourceBytes[1])
          );
        sourceBytes += 2;

        const float decodeScale = static_cast<float>((header & 0x1FFFu) + 1u);
        std::int32_t pairsRemaining = 16;

        do {
          const std::uint8_t nibblePair = static_cast<std::uint8_t>(*sourceBytes++);

          const float sample0 =
            AdxQtblFloat0[nibblePair] * decodeScale + scaledCoef1 * prev1 + scaledCoef0 * prev0;
          *outSamples = static_cast<std::uint16_t>(static_cast<std::int32_t>(sample0) >> 16);

          const float sample1 =
            AdxQtblFloat1[nibblePair] * decodeScale + sample0 * scaledCoef0 + scaledCoef1 * prev0;
          outSamples[1] = static_cast<std::uint16_t>(static_cast<std::int32_t>(sample1) >> 16);

          outSamples += 2;
          prev1 = sample0;
          prev0 = sample1;
          --pairsRemaining;
        } while (pairsRemaining != 0);

        ++processedBlocks;
        if (processedBlocks >= blockCount) {
          break;
        }
      }
    }

    historyLanes[0] = static_cast<std::int16_t>(static_cast<std::int32_t>(prev0) >> 16);
    historyLanes[1] = static_cast<std::int16_t>(static_cast<std::int32_t>(prev1) >> 16);
    return blockCount;
  }

  /**
   * Address: 0x00B2C730 (_ADX_DecodeSteFloatAsSte)
   *
   * What it does:
   * Decodes ADX stereo float-path blocks into discrete L/R PCM lanes.
   */
  int __cdecl ADX_DecodeSteFloatAsSte(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    float coef1Packed
  )
  {
    auto* const leftHistoryLanes = reinterpret_cast<std::int16_t*>(leftHistory);
    auto* const rightHistoryLanes = reinterpret_cast<std::int16_t*>(rightHistory);

    float leftPrev0 = static_cast<float>(leftHistoryLanes[0] << 16);
    float leftPrev1 = static_cast<float>(leftHistoryLanes[1] << 16);
    float rightPrev0 = static_cast<float>(rightHistoryLanes[0] << 16);
    float rightPrev1 = static_cast<float>(rightHistoryLanes[1] << 16);
    int processedHalfBlocks = 0;

    const float scaledCoef0 = static_cast<float>(16 * coef0) * 0.000015258789f;
    const float scaledCoef1 = static_cast<float>(16 * static_cast<std::int16_t>(coef1Packed)) * 0.000015258789f;

    if (blockCount / 2 > 0) {
      while (true) {
        char* const leftHeaderPtr = sourceBytes;
        char* const rightHeaderPtr = sourceBytes + 18;

        if (*leftHeaderPtr < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t leftHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(leftHeaderPtr[0])) << 8) |
            static_cast<std::uint8_t>(leftHeaderPtr[1])
          );
        const float leftScale = static_cast<float>((leftHeader & 0x1FFFu) + 1u);

        if (*rightHeaderPtr < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t rightHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(rightHeaderPtr[0])) << 8) |
            static_cast<std::uint8_t>(rightHeaderPtr[1])
          );
        const float rightScale = static_cast<float>((rightHeader & 0x1FFFu) + 1u);

        std::uint8_t* leftNibbleCursor = reinterpret_cast<std::uint8_t*>(leftHeaderPtr + 2);
        std::uint8_t* rightNibbleCursor = reinterpret_cast<std::uint8_t*>(rightHeaderPtr + 2);
        sourceBytes = reinterpret_cast<char*>(rightNibbleCursor);

        std::int32_t pairsRemaining = 16;
        do {
          const std::uint8_t leftPair = *leftNibbleCursor++;
          const std::uint8_t rightPair = *rightNibbleCursor++;

          const float leftSample0 =
            AdxQtblFloat0[leftPair] * leftScale + scaledCoef1 * leftPrev1 + scaledCoef0 * leftPrev0;
          const float rightSample0 =
            AdxQtblFloat0[rightPair] * rightScale + scaledCoef1 * rightPrev1 + scaledCoef0 * rightPrev0;

          *outLeftSamples = static_cast<std::uint16_t>(static_cast<std::int32_t>(leftSample0) >> 16);
          *outRightSamples = static_cast<std::uint16_t>(static_cast<std::int32_t>(rightSample0) >> 16);

          const float leftSample1 =
            AdxQtblFloat1[leftPair] * leftScale + leftSample0 * scaledCoef0 + scaledCoef1 * leftPrev0;
          const float rightSample1 =
            AdxQtblFloat1[rightPair] * rightScale + rightSample0 * scaledCoef0 + scaledCoef1 * rightPrev0;

          outLeftSamples[1] = static_cast<std::uint16_t>(static_cast<std::int32_t>(leftSample1) >> 16);
          outRightSamples[1] = static_cast<std::uint16_t>(static_cast<std::int32_t>(rightSample1) >> 16);

          outLeftSamples += 2;
          outRightSamples += 2;

          leftPrev1 = leftSample0;
          leftPrev0 = leftSample1;
          rightPrev1 = rightSample0;
          rightPrev0 = rightSample1;
          --pairsRemaining;
        } while (pairsRemaining != 0);

        ++processedHalfBlocks;
        if (processedHalfBlocks >= blockCount / 2) {
          break;
        }
      }
    }

    leftHistoryLanes[0] = static_cast<std::int16_t>(static_cast<std::int32_t>(leftPrev0) >> 16);
    leftHistoryLanes[1] = static_cast<std::int16_t>(static_cast<std::int32_t>(leftPrev1) >> 16);
    rightHistoryLanes[0] = static_cast<std::int16_t>(static_cast<std::int32_t>(rightPrev0) >> 16);
    rightHistoryLanes[1] = static_cast<std::int16_t>(static_cast<std::int32_t>(rightPrev1) >> 16);
    return blockCount;
  }

  /**
   * Address: 0x00B2C9E0 (_ADX_DecodeSteFloatAsMono)
   *
   * What it does:
   * Decodes ADX stereo float-path blocks and writes mixed-mono output lanes.
   */
  int __cdecl ADX_DecodeSteFloatAsMono(
    char* sourceBytes,
    int blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    std::int16_t coef0,
    float coef1Packed
  )
  {
    auto* const leftHistoryLanes = reinterpret_cast<std::int16_t*>(leftHistory);
    auto* const rightHistoryLanes = reinterpret_cast<std::int16_t*>(rightHistory);

    float leftPrev0 = static_cast<float>(leftHistoryLanes[0] << 16);
    float leftPrev1 = static_cast<float>(leftHistoryLanes[1] << 16);
    float rightPrev0 = static_cast<float>(rightHistoryLanes[0] << 16);
    float rightPrev1 = static_cast<float>(rightHistoryLanes[1] << 16);
    int processedHalfBlocks = 0;

    const float scaledCoef0 = static_cast<float>(16 * coef0) * 0.000015258789f;
    const float scaledCoef1 = static_cast<float>(16 * static_cast<std::int16_t>(coef1Packed)) * 0.000015258789f;

    if (blockCount / 2 > 0) {
      while (true) {
        char* const leftHeaderPtr = sourceBytes;
        char* const rightHeaderPtr = sourceBytes + 18;

        if (*leftHeaderPtr < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t leftHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(leftHeaderPtr[0])) << 8) |
            static_cast<std::uint8_t>(leftHeaderPtr[1])
          );
        const float leftScale = static_cast<float>((leftHeader & 0x1FFFu) + 1u);

        if (*rightHeaderPtr < 0) {
          return 2 * processedHalfBlocks;
        }

        const std::uint16_t rightHeader =
          static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(static_cast<std::uint8_t>(rightHeaderPtr[0])) << 8) |
            static_cast<std::uint8_t>(rightHeaderPtr[1])
          );
        const float rightScale = static_cast<float>((rightHeader & 0x1FFFu) + 1u);

        std::uint8_t* leftNibbleCursor = reinterpret_cast<std::uint8_t*>(leftHeaderPtr + 2);
        std::uint8_t* rightNibbleCursor = reinterpret_cast<std::uint8_t*>(rightHeaderPtr + 2);
        sourceBytes = reinterpret_cast<char*>(rightNibbleCursor);

        std::int32_t pairsRemaining = 16;
        do {
          const std::uint8_t leftPair = *leftNibbleCursor++;
          const std::uint8_t rightPair = *rightNibbleCursor++;

          const float leftSample0 =
            AdxQtblFloat0[leftPair] * leftScale + scaledCoef1 * leftPrev1 + scaledCoef0 * leftPrev0;
          const float rightSample0 =
            AdxQtblFloat0[rightPair] * rightScale + scaledCoef1 * rightPrev1 + scaledCoef0 * rightPrev0;

          const std::int32_t mixed0 =
            static_cast<std::int32_t>((rightSample0 + leftSample0) * 0.69999999f) >> 16;
          *outLeftSamples = static_cast<std::uint16_t>(mixed0);
          *outRightSamples = static_cast<std::uint16_t>(mixed0);

          const float leftSample1 =
            AdxQtblFloat1[leftPair] * leftScale + leftSample0 * scaledCoef0 + scaledCoef1 * leftPrev0;
          const float rightSample1 =
            AdxQtblFloat1[rightPair] * rightScale + rightSample0 * scaledCoef0 + scaledCoef1 * rightPrev0;

          const std::int32_t mixed1 =
            static_cast<std::int32_t>((rightSample1 + leftSample1) * 0.69999999f) >> 16;
          outLeftSamples[1] = static_cast<std::uint16_t>(mixed1);
          outRightSamples[1] = static_cast<std::uint16_t>(mixed1);

          outLeftSamples += 2;
          outRightSamples += 2;

          leftPrev1 = leftSample0;
          leftPrev0 = leftSample1;
          rightPrev1 = rightSample0;
          rightPrev0 = rightSample1;
          --pairsRemaining;
        } while (pairsRemaining != 0);

        ++processedHalfBlocks;
        if (processedHalfBlocks >= blockCount / 2) {
          break;
        }
      }
    }

    leftHistoryLanes[0] = static_cast<std::int16_t>(static_cast<std::int32_t>(leftPrev0) >> 16);
    leftHistoryLanes[1] = static_cast<std::int16_t>(static_cast<std::int32_t>(leftPrev1) >> 16);
    rightHistoryLanes[0] = static_cast<std::int16_t>(static_cast<std::int32_t>(rightPrev0) >> 16);
    rightHistoryLanes[1] = static_cast<std::int16_t>(static_cast<std::int32_t>(rightPrev1) >> 16);
    return blockCount;
  }
}
