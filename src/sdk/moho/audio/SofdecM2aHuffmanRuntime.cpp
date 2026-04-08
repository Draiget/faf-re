#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C"
{
  extern std::size_t huffman_codebook[];
  extern std::int32_t book[];
  extern std::size_t spectra_huffman_codebook_parameters[];

  int M2ABSR_Initialize();
  int M2ABSR_Finalize();
  int M2ABSR_Read(std::int32_t bitstreamHandle, std::int32_t bitCount, void* outBits);

  /**
   * Address: 0x00B2B6B0 (m2ahuffman_compare)
   *
   * What it does:
   * Orders codebook rows by `(codeLength, codeword)` ascending.
   */
  int __cdecl m2ahuffman_compare(const void* lhs, const void* rhs)
  {
    const auto* const left = static_cast<const std::uint32_t*>(lhs);
    const auto* const right = static_cast<const std::uint32_t*>(rhs);

    const auto leftLength = left[1];
    const auto rightLength = right[1];
    if (leftLength < rightLength) {
      return -1;
    }

    if (leftLength == rightLength && left[2] < right[2]) {
      return -1;
    }

    return 1;
  }

  /**
   * Address: 0x00B2B630 (m2ahuffman_initialize_table)
   *
   * What it does:
   * Builds one Huffman decode-table descriptor and qsorts decode rows.
   */
  void __cdecl m2ahuffman_initialize_table(
    std::size_t* const tableHeader,
    void* const tableRows,
    std::size_t* const parameters
  )
  {
    const auto maxCoefficient = static_cast<std::int32_t>(parameters[2]);

    if (parameters[0] == 1u) {
      tableHeader[4] = 0;
      tableHeader[3] = static_cast<std::size_t>(maxCoefficient + 1);
    } else {
      tableHeader[3] = static_cast<std::size_t>((2 * maxCoefficient) + 1);
      tableHeader[4] = parameters[2];
    }

    auto dimensions = static_cast<std::int32_t>(parameters[1]);
    std::size_t rowCount = 1;
    if (dimensions > 0) {
      do {
        rowCount *= tableHeader[3];
        --dimensions;
      } while (dimensions != 0);
    }

    tableHeader[0] = rowCount;
    tableHeader[1] = parameters[1];
    tableHeader[2] = parameters[2];
    tableHeader[5] = parameters[0];
    tableHeader[6] = reinterpret_cast<std::size_t>(tableRows);

    qsort(tableRows, rowCount, 0xCu, m2ahuffman_compare);
  }

  /**
   * Address: 0x00B2B5F0 (m2ahuffman_initialize_codebook)
   *
   * What it does:
   * Initializes all spectral Huffman codebook descriptors.
   */
  int __cdecl m2ahuffman_initialize_codebook()
  {
    auto* codebookCursor = &huffman_codebook[7];
    auto* rowCursor = &book[888];
    auto* parameterCursor = &spectra_huffman_codebook_parameters[3];

    do {
      m2ahuffman_initialize_table(codebookCursor, rowCursor, parameterCursor);
      parameterCursor += 3;
      rowCursor += 888;
      codebookCursor += 7;
    } while (parameterCursor <= &spectra_huffman_codebook_parameters[36]);

    return 0;
  }

  /**
   * Address: 0x00B2B5D0 (M2AHUFFMAN_Initialize)
   *
   * What it does:
   * Initializes bitstream helper lane and builds Huffman codebooks.
   */
  int M2AHUFFMAN_Initialize()
  {
    M2ABSR_Initialize();
    m2ahuffman_initialize_codebook();
    return 0;
  }

  /**
   * Address: 0x00B2B6E0 (M2AHUFFMAN_Finalize)
   *
   * What it does:
   * Finalizes bitstream helper lane used by Huffman decode paths.
   */
  int M2AHUFFMAN_Finalize()
  {
    M2ABSR_Finalize();
    return 0;
  }

  /**
   * Address: 0x00B2B6F0 (sub_B2B6F0)
   *
   * What it does:
   * Returns one Huffman codebook descriptor pointer by index.
   */
  int __cdecl M2AHUFFMAN_GetCodebook(const int index, std::uintptr_t* const outCodebook)
  {
    *outCodebook = reinterpret_cast<std::uintptr_t>(&huffman_codebook[7 * index]);
    return 0;
  }

  /**
   * Address: 0x00B2B710 (M2AHUFFMAN_Decode)
   *
   * What it does:
   * Reads one Huffman symbol from bitstream using table row walk.
   */
  int __cdecl M2AHUFFMAN_Decode(int codebookHandle, const int bitstreamHandle)
  {
    auto* entry = reinterpret_cast<std::int32_t*>(codebookHandle);
    std::int32_t bitCount = entry[1];

    std::int32_t codeword = 0;
    M2ABSR_Read(bitstreamHandle, bitCount, &codeword);
    if (codeword != entry[2]) {
      do {
        const std::int32_t previousLength = entry[4];
        entry += 3;

        const std::int32_t extraBits = previousLength - bitCount;
        bitCount += extraBits;

        codeword <<= extraBits;

        std::int32_t suffixBits = 0;
        M2ABSR_Read(bitstreamHandle, extraBits, &suffixBits);
        codeword |= suffixBits;
      } while (codeword != entry[2]);
    }

    return entry[0];
  }

  /**
   * Address: 0x00B2B770 (M2AHUFFMAN_Unpack)
   *
   * What it does:
   * Expands one packed Huffman symbol into 2- or 4-dimensional output lanes
   * and applies sign bits when table requires signed lanes.
   */
  int __cdecl M2AHUFFMAN_Unpack(
    std::uint32_t* const codebook,
    const int packedValue,
    std::int32_t* const outValues,
    std::int32_t* const outDimension,
    const int bitstreamHandle
  )
  {
    const auto radix = static_cast<std::int32_t>(codebook[3]);
    const auto valueOffset = static_cast<std::int32_t>(codebook[4]);
    const auto dimension = static_cast<std::int32_t>(codebook[1]);

    std::int32_t signBit = 0;
    *outDimension = dimension;

    if (dimension == 4) {
      outValues[0] = packedValue / (radix * radix * radix) - valueOffset;

      const auto remainder0 = packedValue - radix * radix * radix * (packedValue / (radix * radix * radix));
      outValues[1] = remainder0 / (radix * radix) - valueOffset;

      const auto remainder1 = remainder0 - radix * radix * (remainder0 / (radix * radix));
      outValues[2] = remainder1 / radix - valueOffset;
      outValues[3] = remainder1 % radix - valueOffset;
    } else if (dimension == 2) {
      outValues[0] = packedValue / radix - valueOffset;
      outValues[1] = packedValue % radix - valueOffset;
    } else {
      return -1;
    }

    if (codebook[5] == 0) {
      return 0;
    }

    for (std::int32_t lane = 0; lane < dimension; ++lane) {
      if (outValues[lane] == 0) {
        continue;
      }

      M2ABSR_Read(bitstreamHandle, 1, &signBit);
      if (signBit == 1) {
        outValues[lane] = -outValues[lane];
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B2B880 (M2AHUFFMAN_GetEscValue)
   *
   * What it does:
   * Resolves escape-coded Huffman value lanes (`abs(value)==16`) by reading
   * unary-prefix length and additional payload bits.
   */
  int __cdecl M2AHUFFMAN_GetEscValue(const int valuesHandle, const int bitstreamHandle)
  {
    auto* const values = reinterpret_cast<std::int32_t*>(valuesHandle);

    std::int32_t bitValue = 0;
    for (int lane = 0; lane < 2; ++lane) {
      std::int32_t value = values[lane];
      if (value < 0) {
        value = -value;
      }

      if (value == 16) {
        std::int32_t additionalBits = 4;
        M2ABSR_Read(bitstreamHandle, 1, &bitValue);

        while (bitValue != 0) {
          ++additionalBits;
          M2ABSR_Read(bitstreamHandle, 1, &bitValue);
        }

        M2ABSR_Read(bitstreamHandle, additionalBits, &bitValue);
        auto decodedValue = (1 << additionalBits) + bitValue;

        if (values[lane] < 0) {
          decodedValue = -decodedValue;
        }

        values[lane] = decodedValue;
      }
    }

    return 0;
  }
}
