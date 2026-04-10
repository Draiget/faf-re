  /**
   * Address: 0x00B2BB20 (_M2ABSR_Tell)
   *
   * What it does:
   * Returns current bit cursor position for one M2A bitstream lane.
   */
  std::int32_t M2ABSR_Tell(const std::int32_t bitstreamHandle, std::int32_t* const outBitPosition)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outBitPosition == nullptr) {
      return -1;
    }

    *outBitPosition = static_cast<std::int32_t>(bitstream->bitPosition);
    return 0;
  }

  /**
   * Address: 0x00B2BB40 (_M2ABSR_IsEndOfBuffer)
   *
   * What it does:
   * Writes whether current bit cursor reached/exceeded the bit-end position.
   */
  std::int32_t M2ABSR_IsEndOfBuffer(const std::int32_t bitstreamHandle, std::int32_t* const outIsEndOfBuffer)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outIsEndOfBuffer == nullptr) {
      return -1;
    }

    *outIsEndOfBuffer = bitstream->bitPosition >= bitstream->bitEndPosition ? 1 : 0;
    return 0;
  }

  /**
   * Address: 0x00B2BB70 (_M2ABSR_Overruns)
   *
   * What it does:
   * Returns overrun counter/status lane from one M2A bitstream context.
   */
  std::int32_t M2ABSR_Overruns(const std::int32_t bitstreamHandle, std::int32_t* const outOverrunCount)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr || outOverrunCount == nullptr) {
      return -1;
    }

    *outOverrunCount = static_cast<std::int32_t>(bitstream->overrunCount);
    return 0;
  }

  /**
   * Address: 0x00B2BB90 (_m2absr_malloc)
   *
   * What it does:
   * Allocates one M2A bitstream/runtime block from heap manager lane when
   * present, otherwise from process heap.
   */
  void* m2absr_malloc(const std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    if (heapManagerHandle != 0) {
      int allocatedPointer = 0;
      HEAPMNG_Allocate(heapManagerHandle, byteCount, &allocatedPointer);
      return reinterpret_cast<void*>(allocatedPointer);
    }

    return HeapAlloc(GetProcessHeap(), 0, byteCount);
  }

  /**
   * Address: 0x00B2BBE0 (_m2absr_free)
   *
   * What it does:
   * Frees one M2A bitstream/runtime block through heap-manager or process-heap
   * lane.
   */
  void m2absr_free(const std::int32_t heapManagerHandle, LPVOID memoryBlock)
  {
    if (heapManagerHandle != 0) {
      HEAPMNG_Free(heapManagerHandle, reinterpret_cast<int>(memoryBlock));
      return;
    }

    HeapFree(GetProcessHeap(), 0, memoryBlock);
  }

  /**
   * Address: 0x00B2BC20 (_m2absr_clear)
   *
   * What it does:
   * Zeroes one memory block for M2A runtime paths.
   */
  std::int32_t m2absr_clear(void* const destination, const unsigned int byteCount)
  {
    std::memset(destination, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B2B910 (M2ABSR_Initialize)
   *
   * What it does:
   * Initializes M2A bitstream runtime lane.
   */
  std::int32_t M2ABSR_Initialize()
  {
    return 0;
  }

  /**
   * Address: 0x00B2B920 (M2ABSR_Finalize)
   *
   * What it does:
   * Finalizes M2A bitstream runtime lane.
   */
  std::int32_t M2ABSR_Finalize()
  {
    return 0;
  }

  /**
   * Address: 0x00B2B930 (M2ABSR_Create)
   *
   * What it does:
   * Allocates and zero-initializes one M2A bitstream state object.
   */
  std::int32_t M2ABSR_Create(const std::int32_t heapManagerHandle, std::int32_t** const outBitstream)
  {
    if (outBitstream == nullptr) {
      return -1;
    }

    auto* const bitstream = static_cast<M2aBitstreamRuntimeView*>(m2absr_malloc(heapManagerHandle, 0x18u));
    if (bitstream == nullptr) {
      return -1;
    }

    m2absr_clear(bitstream, 0x18u);
    *reinterpret_cast<std::int32_t*>(bitstream) = heapManagerHandle;
    *outBitstream = reinterpret_cast<std::int32_t*>(bitstream);
    return 0;
  }

  /**
   * Address: 0x00B2B980 (M2ABSR_Destroy)
   *
   * What it does:
   * Clears one M2A bitstream state object and frees its storage.
   */
  std::int32_t M2ABSR_Destroy(std::int32_t* const bitstreamHandle)
  {
    if (bitstreamHandle == nullptr) {
      return -1;
    }

    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    const auto heapManagerHandle = *reinterpret_cast<std::int32_t*>(bitstream);
    m2absr_clear(bitstream, 0x18u);
    m2absr_free(heapManagerHandle, bitstream);
    return 0;
  }

  /**
   * Address: 0x00B2B9B0 (M2ABSR_Reset)
   *
   * What it does:
   * Clears cursor/end/overrun lanes for one M2A bitstream state.
   */
  std::int32_t M2ABSR_Reset(std::uint32_t* const bitstreamState)
  {
    if (bitstreamState == nullptr) {
      return -1;
    }

    bitstreamState[1] = 0;
    bitstreamState[2] = 0;
    bitstreamState[3] = 0;
    bitstreamState[4] = 0;
    bitstreamState[5] = 0;
    return 0;
  }

  /**
   * Address: 0x00B2B9D0 (M2ABSR_SetBuffer)
   *
   * What it does:
   * Binds one source buffer and byte size to the M2A bitstream state.
   */
  std::int32_t M2ABSR_SetBuffer(
    std::uint32_t* const bitstreamState,
    const std::int32_t sourceBuffer,
    const std::int32_t sourceBytes
  )
  {
    if (bitstreamState == nullptr) {
      return -1;
    }

    bitstreamState[4] = 0;
    bitstreamState[1] = static_cast<std::uint32_t>(sourceBuffer);
    bitstreamState[2] = static_cast<std::uint32_t>(sourceBytes);
    bitstreamState[5] = 0;
    bitstreamState[3] = static_cast<std::uint32_t>(8 * sourceBytes);
    return 0;
  }

  /**
   * Address: 0x00B2BA00 (M2ABSR_Read)
   *
   * What it does:
   * Reads one bounded bit range and advances current bit cursor.
   */
  std::int32_t M2ABSR_Read(
    const std::int32_t bitstreamHandle,
    const std::int32_t bitCount,
    void* const outBits
  )
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    auto* const outBitsValue = static_cast<std::int32_t*>(outBits);
    if (bitstream == nullptr || outBitsValue == nullptr) {
      return -1;
    }

    const auto currentBitPosition = static_cast<std::int32_t>(bitstream->bitPosition);
    const auto newBitPosition = currentBitPosition + bitCount;
    if (newBitPosition > static_cast<std::int32_t>(bitstream->bitEndPosition)) {
      bitstream->overrunCount = 1;
      *outBitsValue = 0;
      return -1;
    }

    std::int32_t readValue = 0;
    std::int32_t remainingBits = bitCount;
    auto currentByteIndex = currentBitPosition >> 3;
    auto currentBitOffset = currentBitPosition & 7;

    if (remainingBits > 0) {
      const auto sourceBase = reinterpret_cast<std::uint8_t*>(
        static_cast<std::uintptr_t>(
          *reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(bitstream) + 0x04)
        )
      );

      auto* sourceCursor = sourceBase + currentByteIndex;
      while (remainingBits > 0) {
        auto chunkBits = 8 - currentBitOffset;
        if (remainingBits < chunkBits) {
          chunkBits = remainingBits;
        }

        remainingBits -= chunkBits;

        const auto byteValue = static_cast<std::uint8_t>(*sourceCursor++);
        const auto shiftedRight = static_cast<std::uint32_t>(byteValue) >> (8 - currentBitOffset - chunkBits);
        const auto chunkMask = static_cast<std::uint32_t>(0xFFu >> (8 - chunkBits));

        readValue = static_cast<std::int32_t>(shiftedRight & chunkMask) + (readValue << chunkBits);
        currentBitOffset = 0;
      }
    }

    *outBitsValue = readValue;
    bitstream->bitPosition = static_cast<std::uint32_t>(newBitPosition);
    return 0;
  }

  /**
   * Address: 0x00B2BAB0 (M2ABSR_AlignToByteBoundary)
   *
   * What it does:
   * Advances bit cursor to next byte boundary.
   */
  std::int32_t M2ABSR_AlignToByteBoundary(const std::int32_t bitstreamHandle)
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr) {
      return -1;
    }

    bitstream->bitPosition = (bitstream->bitPosition + 7u) & 0xFFFFFFF8u;
    return 0;
  }

  /**
   * Address: 0x00B2BAD0 (M2ABSR_Seek)
   *
   * What it does:
   * Sets or offsets the bit cursor using begin/current/end origins.
   */
  std::int32_t M2ABSR_Seek(
    const std::int32_t bitstreamHandle,
    const std::int32_t bitOffset,
    const std::int32_t origin
  )
  {
    auto* const bitstream = reinterpret_cast<M2aBitstreamRuntimeView*>(bitstreamHandle);
    if (bitstream == nullptr) {
      return -1;
    }

    if (origin == 0) {
      bitstream->bitPosition = static_cast<std::uint32_t>(bitOffset);
      return 0;
    }

    if (origin == 1) {
      bitstream->bitPosition = static_cast<std::uint32_t>(static_cast<std::int32_t>(bitstream->bitPosition) + bitOffset);
      return 0;
    }

    if (origin == 2) {
      bitstream->bitPosition = static_cast<std::uint32_t>(bitOffset + static_cast<std::int32_t>(bitstream->bitEndPosition));
      return 0;
    }

    return -1;
  }

