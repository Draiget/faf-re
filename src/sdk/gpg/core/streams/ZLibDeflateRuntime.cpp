#include "gpg/core/streams/ZLibDeflateRuntime.h"

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
