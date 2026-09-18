#include "gpg/core/streams/ZLibDeflateRuntime.h"

#include <array>
#include <cstddef>
#include <cstring>

#include <zlib.h>

#include "zlib/ZLibDeflate.h"
#include "zlib/ZLibInflate.h"

namespace
{
  constexpr std::uint32_t kDeflateMinMatch = 3u;
  constexpr std::uint32_t kDeflateMaxMatch = 258u;
  constexpr std::uint32_t kDeflateMinLookahead = kDeflateMaxMatch + kDeflateMinMatch + 1u; // 262
  constexpr int kDeflateFastNoMatchLength = 2;
  constexpr int kDeflateHeapSize = 573;
  constexpr int kDeflateMaxBits = 15;
  constexpr int kRepeat3To6Code = 16;
  constexpr int kRepeatZero3To10Code = 17;
  constexpr int kRepeatZero11To138Code = 18;
  constexpr int kDeflateLiteralCount = 256;

  constexpr std::array<int, 29> kExtraLengthBits{
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
    1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0
  };

  constexpr std::array<int, 30> kExtraDistanceBits{
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
    9, 9, 10, 10, 11, 11, 12, 12, 13, 13
  };

  [[nodiscard]] constexpr std::array<std::uint8_t, 256> BuildLengthCodeTable() noexcept
  {
    std::array<std::uint8_t, 256> table{};
    std::size_t length = 0;
    int code = 0;
    for (; code < 28; ++code) {
      const std::size_t span = std::size_t{1} << static_cast<std::size_t>(kExtraLengthBits[code]);
      for (std::size_t n = 0; n < span; ++n) {
        table[length++] = static_cast<std::uint8_t>(code);
      }
    }

    table[length - 1] = static_cast<std::uint8_t>(code);
    return table;
  }

  [[nodiscard]] constexpr std::array<std::uint8_t, 512> BuildDistanceCodeTable() noexcept
  {
    std::array<std::uint8_t, 512> table{};
    std::size_t dist = 0;
    int code = 0;
    for (; code < 16; ++code) {
      const std::size_t span = std::size_t{1} << static_cast<std::size_t>(kExtraDistanceBits[code]);
      for (std::size_t n = 0; n < span; ++n) {
        table[dist++] = static_cast<std::uint8_t>(code);
      }
    }

    dist >>= 7u;
    for (; code < 30; ++code) {
      const std::size_t span = std::size_t{1} << static_cast<std::size_t>(kExtraDistanceBits[code] - 7);
      for (std::size_t n = 0; n < span; ++n) {
        table[256u + dist++] = static_cast<std::uint8_t>(code);
      }
    }

    return table;
  }

  constexpr std::array<std::uint8_t, 256> kLengthCode = BuildLengthCodeTable();
  constexpr std::array<std::uint8_t, 512> kDistanceCode = BuildDistanceCodeTable();

  void SendBits(
    DeflateStateRuntimePrefix* const state,
    const unsigned int value,
    const int bitCount
  )
  {
    if (state->bi_valid > (16 - bitCount)) {
      state->bi_buf = static_cast<std::uint16_t>(state->bi_buf | static_cast<std::uint16_t>(value << state->bi_valid));
      state->pending_buf[state->pending++] = static_cast<std::uint8_t>(state->bi_buf & 0xFFu);
      state->pending_buf[state->pending++] = static_cast<std::uint8_t>((state->bi_buf >> 8u) & 0xFFu);
      state->bi_buf = static_cast<std::uint16_t>(value >> (16 - state->bi_valid));
      state->bi_valid += bitCount - 16;
      return;
    }

    state->bi_buf = static_cast<std::uint16_t>(state->bi_buf | static_cast<std::uint16_t>(value << state->bi_valid));
    state->bi_valid += bitCount;
  }

  void SendCode(
    DeflateStateRuntimePrefix* const state,
    const int symbol,
    const DeflateCtDataRuntime* const tree
  )
  {
    SendBits(state, static_cast<unsigned int>(tree[symbol].fc.freq), static_cast<int>(tree[symbol].dl.dad));
  }

  [[nodiscard]] bool IsNodeSmaller(
    const DeflateCtDataRuntime* const tree,
    const int leftNode,
    const int rightNode,
    const std::uint8_t* const depth
  )
  {
    const std::uint16_t leftFrequency = tree[leftNode].fc.freq;
    const std::uint16_t rightFrequency = tree[rightNode].fc.freq;
    return leftFrequency < rightFrequency || (leftFrequency == rightFrequency && depth[leftNode] <= depth[rightNode]);
  }
} // namespace

/**
 * Address: 0x0095A7D0 (FUN_0095A7D0)
 *
 * What it does:
 * Consumes up to `inputLength` bytes while updating the inflate sync marker
 * state lane (`0..4`) and returns the number of consumed bytes.
 */
[[maybe_unused]] unsigned int InflateSyncMarkerScan(
  std::uint32_t* const markerState,
  const std::uint8_t* const inputBytes,
  const unsigned int inputLength
) noexcept
{
  std::uint32_t state = *markerState;
  unsigned int consumed = 0;
  while (consumed < inputLength) {
    if (state >= 4u) {
      break;
    }

    const std::uint8_t value = inputBytes[consumed];
    const std::uint8_t expected = (state < 2u) ? 0u : 0xFFu;
    if (value == expected) {
      ++state;
    } else if (value != 0u) {
      state = 0u;
    } else {
      state = 4u - state;
    }

    ++consumed;
  }

  *markerState = state;
  return consumed;
}

/**
 * Address: 0x0095A830 (FUN_0095A830)
 *
 * What it does:
 * Scans the input stream for the inflate sync marker sequence and transitions
 * back to block decoding when the marker is found.
 */
extern "C" int __cdecl inflateSync(
  z_stream* const stream
)
{
  if (stream == nullptr) {
    return Z_STREAM_ERROR;
  }

  auto* const state = reinterpret_cast<zlib::InflateState*>(stream->state);
  if (state == nullptr) {
    return Z_STREAM_ERROR;
  }

  if (stream->avail_in == 0u && state->bits < 8u) {
    return Z_BUF_ERROR;
  }

  if (state->mode != 0x1D) {
    const std::uint32_t remainderBits = state->bits & 0x7u;
    state->hold <<= remainderBits;
    state->bits -= remainderBits;
    state->mode = 0x1D;

    std::array<std::uint8_t, 4> bufferedBytes{};
    unsigned int bufferedCount = 0u;
    while (state->bits >= 8u) {
      bufferedBytes[bufferedCount++] = static_cast<std::uint8_t>(state->hold & 0xFFu);
      state->hold >>= 8u;
      state->bits -= 8u;
    }

    state->have = 0u;
    (void)InflateSyncMarkerScan(&state->have, bufferedBytes.data(), bufferedCount);
  }

  const unsigned int consumed = InflateSyncMarkerScan(&state->have, stream->next_in, stream->avail_in);
  stream->total_in += consumed;
  stream->avail_in -= consumed;
  stream->next_in += consumed;

  if (state->have != 4u) {
    return Z_DATA_ERROR;
  }

  const uLong preservedTotalIn = stream->total_in;
  const uLong preservedTotalOut = stream->total_out;
  (void)inflateReset(stream);
  stream->total_in = preservedTotalIn;
  stream->total_out = preservedTotalOut;
  state->mode = 0x0B;
  return Z_OK;
}

/**
 * Address: 0x0095AA90 (FUN_0095AA90)
 *
 * What it does:
 * Seeds the deflate history window with one preset dictionary and rebuilds
 * the hash chains used by the match finder.
 */
extern "C" int __cdecl deflateSetDictionary(
  z_stream* const stream,
  const std::uint8_t* const dictionary,
  const unsigned int dictionaryLength
)
{
  if (stream == nullptr || dictionary == nullptr) {
    return Z_STREAM_ERROR;
  }

  auto* const state = reinterpret_cast<zlib::DeflateState*>(stream->state);
  if (state == nullptr) {
    return Z_STREAM_ERROR;
  }

  // The stand-in this used to read through had the two lanes named the wrong
  // way round: +0x04 is `status` and +0x18 is `wrap`, so what it called
  // `status` was the wrap mode. The offsets it used were right, so the gate
  // below is unchanged - it just reads as zlib writes it now.
  const int wrap = state->wrap;
  if (wrap == 2 || (wrap == 1 && state->status != zlib::kDeflateInitState)) {
    return Z_STREAM_ERROR;
  }

  if (wrap != 0) {
    stream->adler = adler32(stream->adler, dictionary, dictionaryLength);
  }

  if (dictionaryLength >= 3u) {
    unsigned int copyLength = dictionaryLength;
    const std::uint8_t* dictionaryTail = dictionary;
    const unsigned int maxDictionaryBytes = state->w_size - 262u;
    if (dictionaryLength > maxDictionaryBytes) {
      copyLength = maxDictionaryBytes;
      dictionaryTail = dictionary + (dictionaryLength - maxDictionaryBytes);
    }

    std::memcpy(state->window, dictionaryTail, copyLength);
    state->strstart = copyLength;
    state->block_start = static_cast<std::int32_t>(copyLength);

    state->ins_h = state->window[0];
    state->ins_h = ((state->ins_h << state->hash_shift) ^ state->window[1]) & state->hash_mask;

    const unsigned int lastInsertIndex = copyLength - 3u;
    for (unsigned int index = 0u; index <= lastInsertIndex; ++index) {
      state->ins_h = ((state->ins_h << state->hash_shift) ^ state->window[index + 2u]) & state->hash_mask;
      state->prev[index & state->w_mask] = state->head[state->ins_h];
      state->head[state->ins_h] = static_cast<std::uint16_t>(index);
    }
  }

  return Z_OK;
}

/**
 * Address: 0x0095B5C0 (FUN_0095B5C0)
 *
 * What it does:
 * Clones one active deflate stream state, including hash/window/pending
 * buffers, so compression can continue from an identical state.
 */
extern "C" int __cdecl deflateCopy(
  z_stream* const destination,
  z_stream* const source
)
{
  if (destination == nullptr || source == nullptr) {
    return Z_STREAM_ERROR;
  }

  auto* const sourceState = reinterpret_cast<zlib::DeflateState*>(source->state);
  if (sourceState == nullptr) {
    return Z_STREAM_ERROR;
  }

  std::memcpy(destination, source, sizeof(z_stream));
  auto* const copiedState = static_cast<zlib::DeflateState*>(
    destination->zalloc(destination->opaque, 1u, static_cast<uInt>(sizeof(zlib::DeflateState)))
  );
  if (copiedState == nullptr) {
    return Z_MEM_ERROR;
  }

  destination->state = reinterpret_cast<internal_state*>(copiedState);
  std::memcpy(copiedState, sourceState, sizeof(zlib::DeflateState));
  copiedState->strm = destination;

  copiedState->window = static_cast<std::uint8_t*>(destination->zalloc(destination->opaque, sourceState->w_size, 2u));
  copiedState->prev = static_cast<std::uint16_t*>(destination->zalloc(destination->opaque, sourceState->w_size, 2u));
  copiedState->head = static_cast<std::uint16_t*>(destination->zalloc(destination->opaque, sourceState->hash_size, 2u));
  copiedState->pending_buf = static_cast<std::uint8_t*>(
    destination->zalloc(destination->opaque, sourceState->lit_bufsize, 4u)
  );

  if (
    copiedState->window == nullptr || copiedState->prev == nullptr || copiedState->head == nullptr ||
    copiedState->pending_buf == nullptr
  ) {
    (void)deflateEnd(destination);
    return Z_MEM_ERROR;
  }

  std::memcpy(copiedState->window, sourceState->window, 2u * static_cast<std::size_t>(sourceState->w_size));
  std::memcpy(copiedState->prev, sourceState->prev, 2u * static_cast<std::size_t>(sourceState->w_size));
  std::memcpy(copiedState->head, sourceState->head, 2u * static_cast<std::size_t>(sourceState->hash_size));
  std::memcpy(copiedState->pending_buf, sourceState->pending_buf, sourceState->pending_buf_size);

  copiedState->pending_out = copiedState->pending_buf + (sourceState->pending_out - sourceState->pending_buf);
  copiedState->d_buf =
    reinterpret_cast<std::uint16_t*>(copiedState->pending_buf + 2u * (sourceState->lit_bufsize >> 1u));
  copiedState->l_buf = copiedState->pending_buf + sourceState->lit_bufsize + 2u * sourceState->lit_bufsize;
  // 0x94 / 0x988 / 0xA7C are dyn_ltree / dyn_dtree / bl_tree, so these are
  // zlib's own three lines rather than offset arithmetic off the block base.
  copiedState->d_desc.dyn_tree = copiedState->dyn_dtree;
  copiedState->l_desc.dyn_tree = copiedState->dyn_ltree;
  copiedState->bl_desc.dyn_tree = copiedState->bl_tree;
  return Z_OK;
}

/**
 * Address: 0x0095C990 (FUN_0095C990)
 *
 * What it does:
 * Returns the embedded zlib version literal for runtime compatibility checks.
 */
extern "C" const char* __cdecl zlibVersion()
{
  return "1.2.3";
}

/**
 * Address: 0x0095D630 (FUN_0095D630)
 *
 * What it does:
 * Combines two packed Adler lanes using the runtime modulo path
 * (`base = 65521`) and returns the merged packed state.
 */
[[maybe_unused]] std::uint32_t Adler32CombinePackedLaneRuntime(
  const std::uint32_t adlerA,
  const std::uint32_t adlerB,
  const std::uint32_t lengthLane
) noexcept
{
  constexpr std::uint32_t kAdlerBase = 65521u;

  const std::uint32_t s1A = static_cast<std::uint16_t>(adlerA);
  const std::uint32_t s2A = adlerA >> 16u;
  const std::uint32_t s1B = static_cast<std::uint16_t>(adlerB);
  const std::uint32_t s2B = adlerB >> 16u;
  const std::uint32_t lengthModBase = lengthLane % kAdlerBase;

  const std::uint32_t productLane = lengthModBase * s1A;
  std::uint32_t sumS1 = s1A + s1B + 65520u;
  const std::uint32_t laneS2 = s2B + s2A - kAdlerBase * (productLane / kAdlerBase) - lengthModBase;
  std::uint32_t sumS2 = productLane + laneS2 + kAdlerBase;

  if (sumS1 > kAdlerBase) {
    sumS1 = s1A + s1B - 1u;
    if (sumS1 > kAdlerBase) {
      sumS1 = s1A + s1B - 65522u;
    }
  }

  if (sumS2 > 0x1FFE2u) {
    sumS2 = productLane + laneS2 - kAdlerBase;
  }
  if (sumS2 > kAdlerBase) {
    sumS2 -= kAdlerBase;
  }

  return sumS1 | (sumS2 << 16u);
}

/**
 * Address: 0x0095D6D0 (FUN_0095D6D0)
 *
 * What it does:
 * Returns the zlib CRC lookup-table base lane.
 */
[[maybe_unused]] const uLongf* RuntimeGetZlibCrcTable() noexcept
{
  return get_crc_table();
}

/**
 * Address: 0x0095DC90 (FUN_0095DC90)
 *
 * What it does:
 * Squares one CRC GF(2) matrix lane (`32` rows) into `destinationMatrix`.
 */
[[maybe_unused]] unsigned int Crc32Gf2MatrixSquare(
  std::uint32_t* const destinationMatrix,
  const std::uint32_t* const sourceMatrix
) noexcept
{
  for (int row = 0; row < 32; ++row) {
    std::uint32_t vector = sourceMatrix[row];
    std::uint32_t sum = 0u;
    const std::uint32_t* column = sourceMatrix;
    while (vector != 0u) {
      if ((vector & 1u) != 0u) {
        sum ^= *column;
      }
      vector >>= 1u;
      ++column;
    }
    destinationMatrix[row] = sum;
  }

  return 0u;
}

namespace
{
  /**
   * Address: 0x0095DC70 (FUN_0095DC70)
   *
   * What it does:
   * Multiplies one CRC GF(2) matrix lane by a bit-vector lane and returns the
   * folded XOR sum.
   */
  [[nodiscard]] std::uint32_t Crc32Gf2MatrixTimes(
    const std::uint32_t* matrix,
    std::uint32_t vector
  ) noexcept
  {
    std::uint32_t sum = 0u;
    while (vector != 0u) {
      if ((vector & 1u) != 0u) {
        sum ^= *matrix;
      }
      vector >>= 1u;
      ++matrix;
    }
    return sum;
  }
}

/**
 * Address: 0x0095DCD0 (FUN_0095DCD0)
 *
 * What it does:
 * Combines one CRC lane (`crc1`) with a second CRC lane (`crc2`) that follows
 * `length` bytes later in the stream, using zlib's GF(2) matrix stepping
 * method.
 */
[[maybe_unused]] std::uint32_t Crc32CombineByLength(
  const std::uint32_t crc1,
  const std::uint32_t crc2,
  std::uint32_t length
) noexcept
{
  if (length == 0u) {
    return crc1;
  }

  std::uint32_t odd[32]{};
  std::uint32_t even[32]{};

  odd[0] = 0xEDB88320u;
  std::uint32_t row = 1u;
  for (int index = 1; index < 32; ++index) {
    odd[index] = row;
    row <<= 1u;
  }

  (void)Crc32Gf2MatrixSquare(even, odd);
  (void)Crc32Gf2MatrixSquare(odd, even);

  std::uint32_t combined = crc1;
  while (true) {
    (void)Crc32Gf2MatrixSquare(even, odd);
    if ((length & 1u) != 0u) {
      combined = Crc32Gf2MatrixTimes(even, combined);
    }
    length >>= 1u;
    if (length == 0u) {
      break;
    }

    (void)Crc32Gf2MatrixSquare(odd, even);
    if ((length & 1u) != 0u) {
      combined = Crc32Gf2MatrixTimes(odd, combined);
    }
    length >>= 1u;
    if (length == 0u) {
      break;
    }
  }

  return crc2 ^ combined;
}

/**
 * Address: 0x0095F140 (FUN_0095F140, bi_windup)
 *
 * What it does:
 * Flushes any pending bit-accumulator bytes into `pending_buf`, then clears
 * the bit-buffer validity lanes.
 */
extern "C" DeflateStateRuntimePrefix* __cdecl bi_windup(
  DeflateStateRuntimePrefix* const state
)
{
  if (state->bi_valid <= 8) {
    if (state->bi_valid > 0) {
      state->pending_buf[state->pending++] = static_cast<std::uint8_t>(state->bi_buf & 0xFFu);
    }
    state->bi_buf = 0;
    state->bi_valid = 0;
    return state;
  }

  state->pending_buf[state->pending] = static_cast<std::uint8_t>(state->bi_buf & 0xFFu);
  state->pending_buf[++state->pending] = static_cast<std::uint8_t>((state->bi_buf >> 8u) & 0xFFu);
  ++state->pending;
  state->bi_buf = 0;
  state->bi_valid = 0;
  return state;
}

/**
 * Address: 0x0095F1C0 (FUN_0095F1C0, copy_block)
 *
 * What it does:
 * Finalizes the bitstream byte boundary, optionally writes the stored-block
 * header, then appends `len` payload bytes into the pending output buffer.
 */
extern "C" void __cdecl copy_block(
  DeflateStateRuntimePrefix* state,
  int len,
  const std::uint8_t* buffer,
  const int header
)
{
  state = bi_windup(state);
  state->last_eob_len = 8;

  if (header != 0) {
    const std::uint16_t lenWord = static_cast<std::uint16_t>(len);
    const std::uint16_t invertedLenWord = static_cast<std::uint16_t>(~lenWord);
    state->pending_buf[state->pending] = static_cast<std::uint8_t>(lenWord & 0xFFu);
    state->pending_buf[++state->pending] = static_cast<std::uint8_t>((lenWord >> 8u) & 0xFFu);
    ++state->pending;
    state->pending_buf[state->pending++] = static_cast<std::uint8_t>(invertedLenWord & 0xFFu);
    state->pending_buf[state->pending++] = static_cast<std::uint8_t>((invertedLenWord >> 8u) & 0xFFu);
  }

  for (; len != 0; --len, ++buffer) {
    state->pending_buf[state->pending] = *buffer;
    ++state->pending;
  }
}

/**
 * Address: 0x0095AC80 (FUN_0095AC80, putShortMSB)
 *
 * What it does:
 * Emits one 16-bit short to the pending output lane in big-endian order.
 */
extern "C" DeflateStateRuntimePrefix* __cdecl putShortMSB(
  DeflateStateRuntimePrefix* const state,
  const std::int16_t value
)
{
  const std::uint16_t word = static_cast<std::uint16_t>(value);
  state->pending_buf[state->pending++] = static_cast<std::uint8_t>((word >> 8u) & 0xFFu);
  state->pending_buf[state->pending++] = static_cast<std::uint8_t>(word & 0xFFu);
  return state;
}

/**
 * Address: 0x0095ACB0 (FUN_0095ACB0, flush_pending)
 *
 * What it does:
 * Copies one bounded pending-buffer span into `stream->next_out`, updates
 * pending/output counters, and rewinds `pendingOut` to `pendingBuffer` when
 * all pending bytes are drained.
 */
[[maybe_unused]] zlib::DeflateState* DeflateFlushPendingToOutput(
  z_stream* const stream
) noexcept
{
  auto* const state = reinterpret_cast<zlib::DeflateState*>(stream->state);
  unsigned int pendingBytes = state->pending;
  if (pendingBytes > stream->avail_out) {
    pendingBytes = stream->avail_out;
  }

  if (pendingBytes != 0u) {
    std::memcpy(stream->next_out, state->pending_out, pendingBytes);
    stream->next_out += pendingBytes;
    state->pending_out += pendingBytes;
    stream->total_out += pendingBytes;
    stream->avail_out -= pendingBytes;
    state->pending -= pendingBytes;
    if (state->pending == 0u) {
      state->pending_out = state->pending_buf;
    }
  }

  return state;
}

/**
 * Address: 0x0095B7D0 (FUN_0095B7D0, lm_init)
 *
 * What it does:
 * Initializes deflate match-finder lanes by clearing hash heads, selecting
 * level-tuned configuration parameters, and resetting start/lookahead state.
 */
[[maybe_unused]] void DeflateInitializeMatchFinderState(
  zlib::DeflateState* const state
) noexcept
{
  state->window_size = state->w_size * 2u;

  state->head[state->hash_size - 1u] = 0u;
  std::memset(state->head, 0, state->hash_size * 2u - 2u);

  const zlib::DeflateConfig& configuration =
    zlib::kConfigurationTable[static_cast<std::size_t>(state->level)];

  state->max_lazy_match = configuration.max_lazy;
  state->good_match = configuration.good_length;
  state->nice_match = configuration.nice_length;
  state->strstart = 0u;
  state->block_start = 0;
  state->lookahead = 0u;
  state->match_available = 0;
  state->ins_h = 0u;
  state->max_chain_length = configuration.max_chain;
  state->prev_length = 2u;
  state->match_length = 2u;
}

/**
 * Address: 0x0095B860 (FUN_0095B860, longest_match)
 *
 * What it does:
 * Walks a bounded hash-chain from `cur_match`, applies zlib's fast guard
 * compares, and records the best match start/length for the current window.
 */
extern "C" unsigned int __cdecl longest_match(
  unsigned int cur_match,
  DeflateStateRuntimePrefix* const state
)
{
  std::uint32_t maxChainLength = state->max_chain_length;
  const std::uint32_t strStart = state->strstart;
  std::uint32_t bestLength = state->prev_length;
  std::uint32_t niceMatch = state->nice_match;
  const std::uint32_t windowSize = state->w_size;

  std::uint8_t* const scanBase = state->window + strStart;
  const std::uint32_t minStrStart = windowSize - kDeflateMinLookahead;
  const std::uint32_t chainLimit = (strStart <= minStrStart) ? 0u : (strStart - windowSize + kDeflateMinLookahead);

  std::uint8_t scanEndMinusOne = scanBase[bestLength - 1u];
  std::uint8_t scanEnd = scanBase[bestLength];
  std::uint8_t* const strEnd = scanBase + kDeflateMaxMatch;

  if (bestLength >= state->good_match) {
    maxChainLength >>= 2u;
  }

  if (niceMatch > state->lookahead) {
    niceMatch = state->lookahead;
  }

  do {
    std::uint8_t* const matchBase = state->window + cur_match;

    if (
      matchBase[bestLength] == scanEnd && matchBase[bestLength - 1u] == scanEndMinusOne && matchBase[0] == scanBase[0]
    ) {
      if (matchBase[1] == scanBase[1]) {
        std::uint8_t* scanCursor = scanBase + 2u;
        std::uint8_t* matchCursor = matchBase + 2u;

        do {
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
          if (*++scanCursor != *++matchCursor) {
            break;
          }
        } while (scanCursor < strEnd);

        const std::uint32_t matchLength = static_cast<std::uint32_t>(scanCursor - scanBase);
        if (matchLength > bestLength) {
          state->match_start = cur_match;
          bestLength = matchLength;
          if (matchLength >= niceMatch) {
            break;
          }
          scanEndMinusOne = scanBase[matchLength - 1u];
          scanEnd = scanBase[matchLength];
        }
      }
    }

    cur_match = state->prev[cur_match & state->w_mask];
    if (cur_match <= chainLimit) {
      break;
    }
    --maxChainLength;
  } while (maxChainLength != 0u);

  if (bestLength <= state->lookahead) {
    return bestLength;
  }
  return state->lookahead;
}

/**
 * Address: 0x0095B9E0 (FUN_0095B9E0, longest_match_fast)
 *
 * What it does:
 * Runs the fast fixed-candidate match lane and returns either the recovered
 * match length or `2` when no usable 3+ byte match is present.
 */
extern "C" int __cdecl longest_match_fast(
  DeflateStateRuntimePrefix* const state,
  const int cur_match
)
{
  std::uint8_t* const scanBase = state->window + state->strstart;
  std::uint8_t* const matchBase = state->window + cur_match;
  std::uint8_t* const strEnd = scanBase + kDeflateMaxMatch;

  if (matchBase[0] != scanBase[0] || matchBase[1] != scanBase[1]) {
    return kDeflateFastNoMatchLength;
  }

  std::uint8_t* scanCursor = scanBase + 2u;
  std::uint8_t* matchCursor = matchBase + 2u;

  do {
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
    if (*++scanCursor != *++matchCursor) {
      break;
    }
  } while (scanCursor < strEnd);

  const int matchLength = static_cast<int>(scanCursor - scanBase);
  if (matchLength < static_cast<int>(kDeflateMinMatch)) {
    return kDeflateFastNoMatchLength;
  }

  state->match_start = static_cast<std::uint32_t>(cur_match);
  if (static_cast<std::uint32_t>(matchLength) > state->lookahead) {
    return static_cast<int>(state->lookahead);
  }
  return matchLength;
}

/**
 * Address: 0x0095DE50 (FUN_0095DE50)
 *
 * What it does:
 * Compresses one in-memory source span into a caller-provided destination
 * span using one temporary z_stream lane and returns zlib-style status codes.
 */
[[maybe_unused]] int DeflateCompressBufferWithRuntimeLevel(
  std::uint8_t* const destinationBuffer,
  unsigned int* const inOutDestinationLength,
  std::uint8_t* const sourceBuffer,
  const unsigned int sourceLength,
  const int compressionLevel
)
{
  z_stream stream;
  stream.next_in = sourceBuffer;
  stream.avail_in = sourceLength;
  stream.next_out = destinationBuffer;
  stream.avail_out = *inOutDestinationLength;
  std::memset(&stream.zalloc, 0, 12u);

  int result = ::deflateInit2_(
    &stream,
    compressionLevel,
    Z_DEFLATED,
    15,
    8,
    0,
    "1.2.3",
    56
  );
  if (result == Z_OK) {
    const int flushStatus = ::deflate(&stream, Z_FINISH);
    if (flushStatus == Z_STREAM_END) {
      *inOutDestinationLength = static_cast<unsigned int>(stream.total_out);
      return ::deflateEnd(&stream);
    }

    (void)::deflateEnd(&stream);
    result = Z_BUF_ERROR;
    if (flushStatus != Z_OK) {
      return flushStatus;
    }
  }

  return result;
}

/**
 * Address: 0x0095DF20 (FUN_0095DF20, compressBound)
 *
 * What it does:
 * Returns zlib's legacy upper bound for compressed output bytes from one
 * source byte count.
 *
 * Called by: deflateBound (0x0095AC40, src/sdk/zlib/ZLibDeflateRuntime.cpp)
 * at 0x0095AC72 when the stream is running the library's default window/hash
 * geometry (w_bits == 15 && hash_bits == 15).
 */
unsigned int compressBoundRuntime(const unsigned int sourceLength)
{
  return sourceLength + (sourceLength >> 12u) + (sourceLength >> 14u) + 11u;
}

/**
 * Address: 0x0095DF50 (FUN_0095DF50, init_block)
 *
 * What it does:
 * Resets dynamic tree frequency lanes and per-block statistics, then seeds the
 * literal end-of-block symbol frequency to one.
 */
extern "C" void __cdecl init_block(
  const int dead,
  DeflateStateRuntimePrefix* const state
)
{
  (void)dead;

  DeflateCtDataRuntime* dynLiteralTree = state->dyn_ltree;
  int literalCount = 286;
  do {
    dynLiteralTree->fc.freq = 0;
    ++dynLiteralTree;
    --literalCount;
  } while (literalCount != 0);

  DeflateCtDataRuntime* dynDistanceTree = state->dyn_dtree;
  int distanceCount = 30;
  do {
    dynDistanceTree->fc.freq = 0;
    ++dynDistanceTree;
    --distanceCount;
  } while (distanceCount != 0);

  DeflateCtDataRuntime* bitLengthTree = state->bl_tree;
  int bitLengthCount = 19;
  do {
    bitLengthTree->fc.freq = 0;
    ++bitLengthTree;
    --bitLengthCount;
  } while (bitLengthCount != 0);

  state->static_len = 0;
  state->opt_len = 0;
  state->matches = 0;
  state->last_lit = 0;
  state->dyn_ltree[256].fc.freq = 1;
}

/**
 * Address: 0x0095E090 (FUN_0095E090, gen_bitlen)
 *
 * What it does:
 * Builds code lengths for one dynamic Huffman tree from parent-depth lanes,
 * updates bit-length histograms, and accumulates opt/static encoded lengths.
 */
extern "C" DeflateStateRuntimePrefix* __cdecl gen_bitlen(
  DeflateStateRuntimePrefix* const state,
  DeflateTreeDescriptorRuntime* const descriptor
)
{
  DeflateCtDataRuntime* const tree = descriptor->dynTree;
  const int maxCode = descriptor->maxCode;
  const DeflateStaticTreeDescriptorRuntime* const staticDescriptor = descriptor->statDesc;
  const DeflateCtDataRuntime* const staticTree = staticDescriptor->staticTree;
  const std::int32_t* const extraBits = staticDescriptor->extraBits;
  const int extraBase = staticDescriptor->extraBase;
  const int maxLength = staticDescriptor->maxLength;

  for (int bits = 0; bits <= kDeflateMaxBits; ++bits) {
    state->bl_count[bits] = 0;
  }

  tree[state->heap[state->heap_max]].dl.len = 0;

  int overflow = 0;
  for (int heapIndex = state->heap_max + 1; heapIndex < kDeflateHeapSize; ++heapIndex) {
    const int node = state->heap[heapIndex];
    int bits = static_cast<int>(tree[tree[node].dl.dad].dl.len) + 1;
    if (bits > maxLength) {
      bits = maxLength;
      ++overflow;
    }

    tree[node].dl.len = static_cast<std::uint16_t>(bits);
    if (node > maxCode) {
      continue;
    }

    ++state->bl_count[bits];
    int extra = 0;
    if (node >= extraBase) {
      extra = extraBits[node - extraBase];
    }

    const std::uint32_t frequency = tree[node].fc.freq;
    state->opt_len += frequency * static_cast<std::uint32_t>(bits + extra);
    if (staticTree != nullptr) {
      state->static_len += frequency * static_cast<std::uint32_t>(staticTree[node].dl.len + extra);
    }
  }

  if (overflow == 0) {
    return state;
  }

  do {
    int bits = maxLength - 1;
    while (state->bl_count[bits] == 0) {
      --bits;
    }

    --state->bl_count[bits];
    state->bl_count[bits + 1] = static_cast<std::uint16_t>(state->bl_count[bits + 1] + 2);
    --state->bl_count[maxLength];
    overflow -= 2;
  } while (overflow > 0);

  int heapIndex = kDeflateHeapSize;
  for (int bits = maxLength; bits != 0; --bits) {
    int nodesAtBits = state->bl_count[bits];
    while (nodesAtBits != 0) {
      const int node = state->heap[--heapIndex];
      if (node <= maxCode) {
        const std::uint16_t nodeLength = tree[node].dl.len;
        if (nodeLength != static_cast<std::uint16_t>(bits)) {
          state->opt_len += static_cast<std::uint32_t>(bits - static_cast<int>(nodeLength)) * tree[node].fc.freq;
          tree[node].dl.len = static_cast<std::uint16_t>(bits);
        }
        --nodesAtBits;
      }
    }
  }

  return state;
}

/**
 * Address: 0x0095DFC0 (FUN_0095DFC0, pqdownheap)
 *
 * What it does:
 * Restores the Huffman min-heap ordering from `heapIndex` using the dynamic
 * tree frequency lane and `depth` tie-break ordering.
 */
extern "C" DeflateStateRuntimePrefix* __cdecl pqdownheap(
  DeflateStateRuntimePrefix* const state,
  DeflateTreeDescriptorRuntime* const descriptor,
  int heapIndex
)
{
  const DeflateCtDataRuntime* const dynamicTree = descriptor->dynTree;
  const int heapLength = state->heap_len;
  const int node = state->heap[heapIndex];
  int childIndex = heapIndex << 1;

  while (childIndex <= heapLength) {
    if (
      childIndex < heapLength &&
      IsNodeSmaller(dynamicTree, state->heap[childIndex + 1], state->heap[childIndex], state->depth)
    ) {
      ++childIndex;
    }

    if (IsNodeSmaller(dynamicTree, node, state->heap[childIndex], state->depth)) {
      break;
    }

    state->heap[heapIndex] = state->heap[childIndex];
    heapIndex = childIndex;
    childIndex <<= 1;
  }

  state->heap[heapIndex] = node;
  return state;
}

/**
 * Address: 0x0095E2B0 (FUN_0095E2B0, scan_tree)
 *
 * What it does:
 * Scans one code-length tree lane and records repeat-run frequencies in
 * `bl_tree` (`REP_3_6`, `REPZ_3_10`, `REPZ_11_138`).
 */
extern "C" void __cdecl scan_tree(
  DeflateCtDataRuntime* const tree,
  const int maxCode,
  DeflateStateRuntimePrefix* const state
)
{
  int nextLength = static_cast<int>(tree->dl.len);
  int count = 0;
  int previousLength = -1;
  int maxCount = 7;
  int minCount = 4;
  if (nextLength == 0) {
    maxCount = 138;
    minCount = 3;
  }

  tree[maxCode + 1].dl.dad = 0xFFFFu;
  if (maxCode < 0) {
    return;
  }

  int remaining = maxCode + 1;
  std::uint16_t* lengthCursor = &tree[1].dl.len;
  do {
    const int currentLength = nextLength;
    nextLength = static_cast<int>(*lengthCursor);
    ++count;
    if (count >= maxCount || currentLength != nextLength) {
      if (count >= minCount) {
        if (currentLength != 0) {
          if (currentLength != previousLength) {
            ++state->bl_tree[currentLength].fc.freq;
          }
          ++state->bl_tree[kRepeat3To6Code].fc.freq;
        } else if (count > 10) {
          ++state->bl_tree[kRepeatZero11To138Code].fc.freq;
        } else {
          ++state->bl_tree[kRepeatZero3To10Code].fc.freq;
        }
      } else {
        state->bl_tree[currentLength].fc.freq =
          static_cast<std::uint16_t>(state->bl_tree[currentLength].fc.freq + count);
      }

      count = 0;
      previousLength = currentLength;
      if (nextLength != 0) {
        if (currentLength == nextLength) {
          maxCount = 6;
          minCount = 3;
        } else {
          maxCount = 7;
          minCount = 4;
        }
      } else {
        maxCount = 138;
        minCount = 3;
      }
    }

    lengthCursor += 2;
    --remaining;
  } while (remaining != 0);
}

/**
 * Address: 0x0095E3A0 (FUN_0095E3A0, send_tree)
 *
 * What it does:
 * Encodes one code-length tree using repeat/run-length control symbols and
 * writes the resulting bits into the pending deflate bitstream.
 */
extern "C" void __cdecl send_tree(
  DeflateStateRuntimePrefix* const state,
  DeflateCtDataRuntime* const tree,
  const int maxCode
)
{
  int count = 0;
  int previousLength = -1;
  int nextLength = static_cast<int>(tree[0].dl.len);
  int maxCount = 7;
  int minCount = 4;

  if (nextLength == 0) {
    maxCount = 138;
    minCount = 3;
  }

  for (int symbolIndex = 0; symbolIndex <= maxCode; ++symbolIndex) {
    const int currentLength = nextLength;
    nextLength = static_cast<int>(tree[symbolIndex + 1].dl.len);
    ++count;

    if (count < maxCount && currentLength == nextLength) {
      continue;
    }

    if (count < minCount) {
      do {
        SendCode(state, currentLength, state->bl_tree);
        --count;
      } while (count != 0);
    } else if (currentLength != 0) {
      if (currentLength != previousLength) {
        SendCode(state, currentLength, state->bl_tree);
        --count;
      }
      SendCode(state, kRepeat3To6Code, state->bl_tree);
      SendBits(state, static_cast<unsigned int>(count - 3), 2);
    } else if (count <= 10) {
      SendCode(state, kRepeatZero3To10Code, state->bl_tree);
      SendBits(state, static_cast<unsigned int>(count - 3), 3);
    } else {
      SendCode(state, kRepeatZero11To138Code, state->bl_tree);
      SendBits(state, static_cast<unsigned int>(count - 11), 7);
    }

    count = 0;
    previousLength = currentLength;
    if (nextLength == 0) {
      maxCount = 138;
      minCount = 3;
    } else if (currentLength == nextLength) {
      maxCount = 6;
      minCount = 3;
    } else {
      maxCount = 7;
      minCount = 4;
    }
  }
}

/**
 * Address: 0x0095EB20 (FUN_0095EB20, _tr_tally)
 *
 * What it does:
 * Appends one literal/match token into `l_buf`/`d_buf`, updates dynamic
 * Huffman frequency lanes, and returns true when the literal buffer reaches
 * its last writable slot.
 */
extern "C" int __cdecl _tr_tally(
  DeflateStateRuntime* const state,
  const int distance,
  const int literalOrLengthCode
)
{
  const std::uint32_t literalIndex = state->last_lit;
  state->d_buf[literalIndex] = static_cast<std::uint16_t>(distance);
  state->l_buf[literalIndex] = static_cast<std::uint8_t>(literalOrLengthCode);
  ++state->last_lit;

  if (distance != 0) {
    ++state->matches;
    const std::uint32_t lengthCode = kLengthCode[static_cast<std::uint8_t>(literalOrLengthCode)];
    ++state->dyn_ltree[lengthCode + kDeflateLiteralCount + 1].fc.freq;

    const std::uint32_t distanceMinusOne = static_cast<std::uint32_t>(distance - 1);
    const std::uint32_t distanceCode = distanceMinusOne < 256u
      ? kDistanceCode[distanceMinusOne]
      : kDistanceCode[(distanceMinusOne >> 7u) + 256u];
    ++state->dyn_dtree[distanceCode].fc.freq;
  } else {
    ++state->dyn_ltree[static_cast<std::uint8_t>(literalOrLengthCode)].fc.freq;
  }

  return state->last_lit == (state->lit_bufsize - 1u) ? 1 : 0;
}

/**
 * Address: 0x0095EFD0 (FUN_0095EFD0, set_data_type)
 *
 * What it does:
 * Scans literal frequency lanes using zlib's text/binary heuristic windows and
 * stores the inferred data-type flag through `state->strm->data_type`.
 */
extern "C" void __cdecl set_data_type(
  const int dead,
  DeflateStateRuntimePrefix* const state
)
{
  (void)dead;

  int n = 0;
  DeflateCtDataRuntime* dynLiteralTree = state->dyn_ltree;
  do {
    if (dynLiteralTree->fc.freq != 0u) {
      break;
    }
    ++n;
    ++dynLiteralTree;
  } while (n < 9);

  if (n == 9) {
    n = 14;
    for (DeflateCtDataRuntime* literalCursor = &state->dyn_ltree[15]; literalCursor[-1].fc.freq == 0u;
         literalCursor += 6) {
      if (literalCursor[0].fc.freq != 0u) {
        state->strm->data_type = (n == 31) ? 1 : 0;
        return;
      }
      if (literalCursor[1].fc.freq != 0u) {
        state->strm->data_type = (n == 30) ? 1 : 0;
        return;
      }
      if (literalCursor[2].fc.freq != 0u) {
        state->strm->data_type = (n == 29) ? 1 : 0;
        return;
      }
      if (literalCursor[3].fc.freq != 0u) {
        state->strm->data_type = (n == 28) ? 1 : 0;
        return;
      }
      if (literalCursor[4].fc.freq != 0u) {
        n += 5;
        break;
      }

      n += 6;
      if (n >= 32) {
        state->strm->data_type = (n == 32) ? 1 : 0;
        return;
      }
    }
  }

  state->strm->data_type = (n == 32) ? 1 : 0;
}
