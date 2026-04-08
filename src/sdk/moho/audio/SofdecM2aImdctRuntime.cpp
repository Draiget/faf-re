#include <cmath>
#include <cstdint>
#include <cstring>

extern "C"
{
  extern float sin_long[];
  extern float dolby_long[];
  extern float sin_start[];
  extern float dolby_start[];
  extern float sin_short[];
  extern float dolby_short[];
  extern float sin_stop[];
  extern float dolby_stop[];

  extern float m2aimdct_work[];
  extern float m2aimdct_sorted[];
  extern float m2aimdct_pcm256[];
  extern float m2aimdct_cos_table_long[];
  extern float m2aimdct_sin_table_long[];
  extern float m2aimdct_cos_table_long_m4[];
  extern float m2aimdct_sin_table_long_m4[];
  extern float m2aimdct_cos_table_short[];
  extern float m2aimdct_sin_table_short[];
  extern float flt_1204CFC[];
  extern float flt_1205AFC[];
  extern float flt_1205B00[];
  extern float flt_120ABFC[];
  extern float flt_12054FC[];

  namespace
  {
    constexpr double kPi = 3.14159265358979323846;
    constexpr float kLongTableTailScale = 0.00069053395f;
    constexpr float kShortTableTailScale = 0.0055242716f;
    constexpr float kNegativeOne = -1.0f;
  }

  /**
   * Address: 0x00B2ADF0 (_m2aimdct_initialize_table_long)
   *
   * What it does:
   * Builds long-window IMDCT cosine/sine tables and applies tail scaling lanes.
   */
  void __cdecl m2aimdct_initialize_table_long()
  {
    double stageScale = 1.0;
    int stageIndex = 0;
    int tableWriteBaseBytes = 0;
    int stageLength = 1024;

    do {
      stageLength /= 2;
      if (stageLength > 0) {
        int sampleIndex = 0;
        int writeOffsetBytes = tableWriteBaseBytes;
        const int stageLaneBase = stageIndex << 9;

        do {
          const double angle =
            (static_cast<double>((2 * sampleIndex) + 1) * kPi) / (4096.0 * stageScale);
          m2aimdct_cos_table_long[writeOffsetBytes / 4] =
            static_cast<float>(std::cos(angle));
          m2aimdct_sin_table_long[writeOffsetBytes / 4] =
            static_cast<float>(-std::sin(angle));

          if (tableWriteBaseBytes > 0) {
            for (int stageBit = 0; stageBit < stageIndex; ++stageBit) {
              int repeatCount = 1 << stageBit;
              if (repeatCount <= 0) {
                continue;
              }

              const int strideBytes = 4 * stageLength;
              int sourceOffsetBytes = writeOffsetBytes;
              int destinationOffsetBytes =
                4 * (sampleIndex + stageLaneBase + (stageLength * repeatCount));

              do {
                m2aimdct_cos_table_long[destinationOffsetBytes / 4] =
                  m2aimdct_cos_table_long[sourceOffsetBytes / 4];
                m2aimdct_sin_table_long[destinationOffsetBytes / 4] =
                  -m2aimdct_sin_table_long[sourceOffsetBytes / 4];

                sourceOffsetBytes += strideBytes;
                destinationOffsetBytes += strideBytes;
                --repeatCount;
              } while (repeatCount != 0);
            }
          }

          ++sampleIndex;
          writeOffsetBytes += 4;
        } while (sampleIndex < stageLength);
      }

      stageScale *= 0.5;
      ++stageIndex;
      tableWriteBaseBytes += 2048;
    } while (stageLength > 1);

    for (int index = 0; index < 512;) {
      const float scaledCos =
        m2aimdct_cos_table_long[4608 + index] * kLongTableTailScale;
      m2aimdct_cos_table_long[++index + 4607] = scaledCos;
      flt_1204CFC[index] *= kLongTableTailScale;
    }
  }

  /**
   * Address: 0x00B2AF40 (_m2aimdct_initialize_table_short)
   *
   * What it does:
   * Builds short-window IMDCT cosine/sine tables and applies tail scaling lanes.
   */
  void __cdecl m2aimdct_initialize_table_short()
  {
    double stageScale = 1.0;
    int stageIndex = 0;
    int tableWriteBaseBytes = 0;
    int stageLength = 128;

    do {
      stageLength /= 2;
      if (stageLength > 0) {
        int sampleIndex = 0;
        int writeOffsetBytes = tableWriteBaseBytes;
        const int stageLaneBase = stageIndex << 6;

        do {
          const double angle =
            (static_cast<double>((2 * sampleIndex) + 1) * kPi) / (512.0 * stageScale);
          m2aimdct_cos_table_short[writeOffsetBytes / 4] =
            static_cast<float>(std::cos(angle));
          m2aimdct_sin_table_short[writeOffsetBytes / 4] =
            static_cast<float>(-std::sin(angle));

          if (tableWriteBaseBytes > 0) {
            for (int stageBit = 0; stageBit < stageIndex; ++stageBit) {
              int repeatCount = 1 << stageBit;
              if (repeatCount <= 0) {
                continue;
              }

              const int strideBytes = 4 * stageLength;
              int sourceOffsetBytes = writeOffsetBytes;
              int destinationOffsetBytes =
                4 * (sampleIndex + stageLaneBase + (stageLength * repeatCount));

              do {
                m2aimdct_cos_table_short[destinationOffsetBytes / 4] =
                  m2aimdct_cos_table_short[sourceOffsetBytes / 4];
                m2aimdct_sin_table_short[destinationOffsetBytes / 4] =
                  -m2aimdct_sin_table_short[sourceOffsetBytes / 4];

                sourceOffsetBytes += strideBytes;
                destinationOffsetBytes += strideBytes;
                --repeatCount;
              } while (repeatCount != 0);
            }
          }

          ++sampleIndex;
          writeOffsetBytes += 4;
        } while (sampleIndex < stageLength);
      }

      stageScale *= 0.5;
      ++stageIndex;
      tableWriteBaseBytes += 256;
    } while (stageLength > 1);

    for (int index = 0; index < 64;) {
      const float scaledCos = flt_1205B00[index++] * kShortTableTailScale;
      flt_1205AFC[index] = scaledCos;
      m2aimdct_sin_table_short[index + 383] *= kShortTableTailScale;
    }
  }

  /**
   * Address: 0x00B2B0C0 (_m2aimdct_prep_proc_long)
   *
   * What it does:
   * Executes staged butterfly prep pass for long-window IMDCT runtime.
   */
  int __cdecl m2aimdct_prep_proc_long(float* sourceSpectral, float* scratchBuffer)
  {
    float* activeSource = sourceSpectral;
    float* activeScratch = scratchBuffer;
    int stageWidth = 1;

    while (true) {
      const int segmentLength = 512 / stageWidth;
      float* segmentWriteBase = activeScratch + segmentLength;

      if (stageWidth > 0) {
        int stageCounter = stageWidth;
        const int stageStride = 1024 / stageWidth;

        do {
          for (int lane = 0; lane < segmentLength; ++lane) {
            segmentWriteBase[lane - segmentLength] =
              activeSource[(2 * lane)] + activeSource[(2 * lane) + 1];
            segmentWriteBase[lane] =
              activeSource[(2 * lane)] - activeSource[(2 * lane) + 1];
          }

          activeSource += stageStride;
          segmentWriteBase += stageStride;
          --stageCounter;
        } while (stageCounter != 0);
      }

      stageWidth *= 2;
      float* nextScratch = activeSource - 1024;
      activeSource = activeScratch;
      activeScratch = nextScratch;

      if (stageWidth >= 1024) {
        break;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2B170 (_m2aimdct_main_proc_long)
   *
   * What it does:
   * Executes long-window IMDCT core pass and writes folded output lanes.
   */
  int __cdecl m2aimdct_main_proc_long(float* inputSpectral, float* outputBuffer)
  {
    float* activeInput = inputSpectral;
    float* activeScratch = m2aimdct_work;

    int stageWindow = 1024;
    int stageBlockCount = 1;
    int angleTableBase = 4608;

    while (true) {
      stageBlockCount *= 2;
      const int stageStride = stageBlockCount;
      stageWindow /= 2;
      const int halfStride = stageStride / 2;

      if (stageWindow > 0) {
        int blockBase = 0;
        float* stageInputCursor = activeInput;
        float* stageCosOutput = activeScratch;
        float* stageSinOutput = activeInput + halfStride;
        float* stageMirrorOutput = &activeScratch[stageStride - 1];
        int blocksRemaining = stageWindow;

        do {
          if (halfStride > 0) {
            float* leftCursor = stageInputCursor;
            float* rightCursor = stageSinOutput;
            float* cosOutCursor = stageCosOutput;
            float* mirrorOutCursor = stageMirrorOutput;

            int angleIndex = angleTableBase + blockBase;
            int lanesRemaining = halfStride;
            do {
              const float left = *leftCursor;
              const float right = *rightCursor;

              ++cosOutCursor;
              ++rightCursor;
              ++angleIndex;
              ++leftCursor;
              mirrorOutCursor -= 4;
              --lanesRemaining;

              *(cosOutCursor - 1) =
                m2aimdct_cos_table_long[angleIndex] * left -
                m2aimdct_sin_table_long[angleIndex] * right;
              *(mirrorOutCursor + 4) =
                m2aimdct_sin_table_long_m4[angleIndex] * *(leftCursor - 1) +
                m2aimdct_cos_table_long_m4[angleIndex] * *(rightCursor - 1);
            } while (lanesRemaining != 0);

            activeInput = inputSpectral;
            activeScratch = m2aimdct_work;
          }

          stageSinOutput += 2 * halfStride;
          stageCosOutput += stageStride;
          stageMirrorOutput += 4 * stageStride;
          blockBase += halfStride;
          stageInputCursor += 2 * halfStride;
          --blocksRemaining;
        } while (blocksRemaining != 0);
      }

      float* const swapCursor = activeInput;
      activeInput = activeScratch;
      activeScratch = swapCursor;
      angleTableBase -= 512;

      if (stageWindow <= 1) {
        break;
      }
    }

    float* tailCursor = activeInput + 1023;
    int tailCount = 1024;
    float* tailWrite = outputBuffer + 512;
    do {
      *tailWrite++ = *tailCursor-- * kNegativeOne;
      --tailCount;
    } while (tailCount != 0);

    int mirrorIndex = 512;
    float* mirrorWrite = outputBuffer + 511;
    do {
      *mirrorWrite-- = outputBuffer[mirrorIndex++] * kNegativeOne;
    } while (mirrorIndex < 1024);

    int copyIndex = 1024;
    auto* copyWrite = reinterpret_cast<std::uint32_t*>(outputBuffer + 2047);
    do {
      *copyWrite-- =
        reinterpret_cast<std::uint32_t*>(outputBuffer)[copyIndex++];
    } while (copyIndex < 1536);

    return 0;
  }

  /**
   * Address: 0x00B2B090 (_m2aimdct_transform_long)
   *
   * What it does:
   * Runs long-window IMDCT prep+main chain into output buffer.
   */
  int __cdecl m2aimdct_transform_long(float* inputSpectral, float* outputBuffer)
  {
    m2aimdct_prep_proc_long(inputSpectral, m2aimdct_sorted);
    m2aimdct_main_proc_long(m2aimdct_sorted, outputBuffer);
    return 0;
  }

  /**
   * Address: 0x00B2B360 (_m2aimdct_prep_proc_short)
   *
   * What it does:
   * Executes staged butterfly prep pass for short-window IMDCT runtime.
   */
  int __cdecl m2aimdct_prep_proc_short(float* sourceSpectral, float* scratchBuffer)
  {
    float* activeSource = sourceSpectral;
    float* activeScratch = scratchBuffer;
    int stageWidth = 1;

    while (true) {
      const int segmentLength = 64 / stageWidth;
      float* segmentWriteBase = activeScratch + segmentLength;

      if (stageWidth > 0) {
        int stageCounter = stageWidth;
        const int stageStride = 128 / stageWidth;

        do {
          for (int lane = 0; lane < segmentLength; ++lane) {
            segmentWriteBase[lane - segmentLength] =
              activeSource[(2 * lane)] + activeSource[(2 * lane) + 1];
            segmentWriteBase[lane] =
              activeSource[(2 * lane)] - activeSource[(2 * lane) + 1];
          }

          activeSource += stageStride;
          segmentWriteBase += stageStride;
          --stageCounter;
        } while (stageCounter != 0);
      }

      stageWidth *= 2;
      float* nextScratch = activeSource - 128;
      activeSource = activeScratch;
      activeScratch = nextScratch;

      if (stageWidth >= 128) {
        break;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2B410 (_m2aimdct_main_proc_short)
   *
   * What it does:
   * Runs short-window IMDCT core pass and writes folded output lanes.
   */
  int __cdecl m2aimdct_main_proc_short(float* inputSpectral, float* outputBuffer)
  {
    float* activeInput = inputSpectral;
    float* activeScratch = m2aimdct_work;

    int stageWindow = 128;
    int stageBlockCount = 1;
    int angleTableBase = 384;

    while (true) {
      stageBlockCount *= 2;
      const int stageStride = stageBlockCount;
      stageWindow /= 2;
      const int halfStride = stageStride / 2;

      if (stageWindow > 0) {
        int blockBase = 0;
        float* stageInputCursor = activeInput;
        float* stageCosOutput = activeScratch;
        float* stageSinOutput = activeInput + halfStride;
        float* stageMirrorOutput = &activeScratch[stageStride - 1];
        int blocksRemaining = stageWindow;

        do {
          if (halfStride > 0) {
            float* leftCursor = stageInputCursor;
            float* rightCursor = stageSinOutput;
            float* cosOutCursor = stageCosOutput;
            float* mirrorOutCursor = stageMirrorOutput;

            int angleIndex = angleTableBase + blockBase;
            int lanesRemaining = halfStride;
            do {
              const float left = *leftCursor;
              const float right = *rightCursor;

              ++cosOutCursor;
              ++rightCursor;
              ++angleIndex;
              ++leftCursor;
              mirrorOutCursor -= 4;
              --lanesRemaining;

              *(cosOutCursor - 1) =
                m2aimdct_cos_table_short[angleIndex] * left -
                m2aimdct_sin_table_short[angleIndex] * right;
              *(mirrorOutCursor + 4) =
                flt_120ABFC[angleIndex] * *(leftCursor - 1) +
                flt_12054FC[angleIndex] * *(rightCursor - 1);
            } while (lanesRemaining != 0);

            activeInput = inputSpectral;
            activeScratch = m2aimdct_work;
          }

          stageSinOutput += 2 * halfStride;
          stageCosOutput += stageStride;
          stageMirrorOutput += 4 * stageStride;
          blockBase += halfStride;
          stageInputCursor += 2 * halfStride;
          --blocksRemaining;
        } while (blocksRemaining != 0);
      }

      float* const swapCursor = activeInput;
      activeInput = activeScratch;
      activeScratch = swapCursor;
      angleTableBase -= 64;

      if (stageWindow <= 1) {
        break;
      }
    }

    float* tailCursor = activeInput + 127;
    int tailCount = 128;
    float* tailWrite = outputBuffer + 64;
    do {
      *tailWrite++ = *tailCursor-- * kNegativeOne;
      --tailCount;
    } while (tailCount != 0);

    int mirrorIndex = 64;
    float* mirrorWrite = outputBuffer + 63;
    do {
      *mirrorWrite-- = outputBuffer[mirrorIndex++] * kNegativeOne;
    } while (mirrorIndex < 128);

    int copyIndex = 128;
    auto* copyWrite = reinterpret_cast<std::uint32_t*>(outputBuffer + 255);
    do {
      *copyWrite-- =
        reinterpret_cast<std::uint32_t*>(outputBuffer)[copyIndex++];
    } while (copyIndex < 192);

    return 0;
  }

  /**
   * Address: 0x00B2B330 (_m2aimdct_transform_short)
   *
   * What it does:
   * Runs short-window IMDCT prep+main chain into output buffer.
   */
  int __cdecl m2aimdct_transform_short(float* inputSpectral, float* outputBuffer)
  {
    m2aimdct_prep_proc_short(inputSpectral, m2aimdct_sorted);
    m2aimdct_main_proc_short(m2aimdct_sorted, outputBuffer);
    return 0;
  }

  /**
   * Address: 0x00B2ABF0 (_M2AIMDCT_Initialize)
   *
   * What it does:
   * Initializes long+short IMDCT coefficient tables.
   */
  int M2AIMDCT_Initialize()
  {
    m2aimdct_initialize_table_long();
    m2aimdct_initialize_table_short();
    return 0;
  }

  /**
   * Address: 0x00B2AC00 (_M2AIMDCT_Finalize)
   *
   * What it does:
   * IMDCT finalize stub; returns success without teardown work.
   */
  int M2AIMDCT_Finalize()
  {
    return 0;
  }

  /**
   * Address: 0x00B2AC10 (_M2AIMDCT_GetWindow)
   *
   * What it does:
   * Returns IMDCT window table pointer by `(windowSequence, windowShape)`.
   */
  float* __cdecl M2AIMDCT_GetWindow(int windowSequence, int windowShape)
  {
    switch (windowShape + (2 * windowSequence)) {
      case 0:
        return sin_long;
      case 1:
        return dolby_long;
      case 2:
        return sin_start;
      case 3:
        return dolby_start;
      case 4:
        return sin_short;
      case 5:
        return dolby_short;
      case 6:
        return sin_stop;
      case 7:
        return dolby_stop;
      default:
        return nullptr;
    }
  }

  /**
   * Address: 0x00B2AC80 (_M2AIMDCT_TransformLong)
   *
   * What it does:
   * Runs long IMDCT core and applies previous/current window envelopes.
   */
  int __cdecl M2AIMDCT_TransformLong(
    float* spectralData,
    void* previousWindowRaw,
    void* currentWindowRaw,
    float* overlapBuffer
  )
  {
    const auto* previousWindow = static_cast<const float*>(previousWindowRaw);
    const auto* currentWindow = static_cast<const float*>(currentWindowRaw);
    m2aimdct_transform_long(spectralData, overlapBuffer);

    float* writeCursor = overlapBuffer;
    for (int index = 0; index < 1024; ++index) {
      writeCursor[index] *= previousWindow[index];
    }

    float* secondHalf = overlapBuffer + 1024;
    for (int index = 0; index < 1024; ++index) {
      secondHalf[index] *= currentWindow[index + 1024];
    }

    return 0;
  }

  /**
   * Address: 0x00B2ACD0 (_M2AIMDCT_TransformShort)
   *
   * What it does:
   * Runs short IMDCT chain across 8 windows and merges overlap-add lanes.
   */
  int __cdecl M2AIMDCT_TransformShort(
    float* spectralData,
    void* previousWindowRaw,
    void* currentWindowRaw,
    float* overlapBufferRaw
  )
  {
    const auto* previousWindow = static_cast<const float*>(previousWindowRaw);
    const auto* currentWindow = static_cast<const float*>(currentWindowRaw);
    auto* overlapBuffer = reinterpret_cast<std::uint32_t*>(overlapBufferRaw);

    std::memset(overlapBuffer, 0, 0x700u);
    std::memset(overlapBuffer + 1600, 0, 0x700u);

    auto* writeWindow = overlapBuffer + 448;
    m2aimdct_transform_short(spectralData, m2aimdct_pcm256);

    for (float* lane = m2aimdct_pcm256; lane < &m2aimdct_pcm256[128]; ++lane) {
      *lane *= previousWindow[lane - m2aimdct_pcm256];
    }

    for (float* lane = &m2aimdct_pcm256[128], *window = const_cast<float*>(currentWindow + 128);
         lane < m2aimdct_sorted;
         ++lane, ++window) {
      *lane *= *window;
    }

    {
      auto* source = reinterpret_cast<std::uint32_t*>(m2aimdct_pcm256);
      for (int lane = 0; lane < 256; ++lane) {
        writeWindow[lane] = source[lane];
      }
    }

    float* spectralCursor = spectralData;
    std::intptr_t sourceOffsetBytes =
      reinterpret_cast<std::intptr_t>(m2aimdct_pcm256) -
      reinterpret_cast<std::intptr_t>(writeWindow);

    std::uint32_t* result = writeWindow + 256;
    for (int windowIndex = 0; windowIndex < 7; ++windowIndex) {
      spectralCursor += 128;
      m2aimdct_transform_short(spectralCursor, m2aimdct_pcm256);

      for (float* lane = m2aimdct_pcm256; lane < m2aimdct_sorted; ++lane) {
        *lane *= currentWindow[lane - m2aimdct_pcm256];
      }

      writeWindow += 128;
      sourceOffsetBytes -= 512;

      {
        auto* accumulateLane = reinterpret_cast<float*>(writeWindow);
        for (int lane = 0; lane < 128; ++lane) {
          const auto sourceAddress =
            reinterpret_cast<std::intptr_t>(&accumulateLane[lane]) + sourceOffsetBytes;
          const float sourceValue = *reinterpret_cast<const float*>(sourceAddress);
          accumulateLane[lane] += sourceValue;
        }
      }

      result = writeWindow + 128;
      for (int lane = 0; lane < 128; ++lane) {
        const auto sourceAddress =
          reinterpret_cast<std::intptr_t>(&result[lane]) + sourceOffsetBytes;
        result[lane] = *reinterpret_cast<const std::uint32_t*>(sourceAddress);
      }
    }

    (void)result;
    return 0;
  }
}
