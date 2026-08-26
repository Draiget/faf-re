// zlib deflate runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). These recovered bodies match the binary at their given addresses
// and override the library copies via .obj-before-.lib resolution; the TU is
// ExcludedFromBuild (a source-faithful record verified per-TU + standalone).
//
// The whole deflate (compress) pipeline is recovered here, walked from the
// deflate/deflateInit2_ call closure:
//   public API : deflateInit2_ (0x0095C740), deflateReset (0x0095C5E0),
//                deflate (0x0095AD00), deflateEnd (0x0095B4E0)
//   driver     : PutShortMSB (0x0095AC80), FlushPending (0x0095ACB0)
//   compress   : DeflateStored (0x0095BC00), DeflateFast (0x0095BDE0),
//                DeflateSlow (0x0095C150)
//   match/win  : FillWindow (0x0095BAB0), LongestMatch (0x0095B860),
//                LongestMatchFast (0x0095B9E0), ReadBuf (inlined)
//   trees      : TreeInit (0x0095F250), InitBlock (0x0095DF50),
//                LmInit (0x0095B7D0), TreeFlushBlock (0x0095F8B0),
//                TreeStoredBlock (0x0095F620), TreeAlign (0x0095F6C0),
//                BuildTree (0x0095F350), BuildBlTree (0x0095F550),
//                ScanTree (0x0095E2B0), SendTree (0x0095E3A0),
//                SendAllTrees (0x0095E8C0), CompressBlock (0x0095EBC0),
//                GenBitlen (0x0095E090), GenCodes (0x0095F2C0),
//                PqDownHeap (0x0095DFC0), SetDataType (0x0095EFD0),
//                BiWindup (0x0095F140), BiFlush (0x0095F0C0),
//                CopyBlock (0x0095F1C0)
//
// adler32/crc32 live in sibling TUs (ZLibAdlerRuntime.cpp / ZLibCrcRuntime.cpp)
// and are called here by name (extern "C").

#include <cstring>

#include "zlib/ZLibDeflate.h"

extern "C" unsigned long adler32(unsigned long adler, const unsigned char* buf, unsigned int len);
extern "C" unsigned long crc32(unsigned long crc, const unsigned char* buf, unsigned int len);

// The zlib default allocators (zcalloc/zcfree) are provided by the inflate side
// of the recovered runtime; deflateInit2_ installs them when the caller passes a
// null zalloc/zfree, exactly as the binary does.
extern "C" void* zcalloc(void* opaque, unsigned int items, unsigned int size);
extern "C" void  zcfree(void* opaque, void* ptr);

// deflateInit2_ frees a partially-allocated state via deflateEnd (defined at the
// bottom of this TU); forward-declare so the mem-error path can reach it.
extern "C" int deflateEnd(zlib::ZStream* strm);

// compressBound's legacy formula lives in the sibling gpg/core/streams TU
// (0x0095DF20); deflateBound below calls it exactly as the binary does at
// 0x0095AC72. Plain C++ linkage (not extern "C"), matching its real definition.
unsigned int compressBoundRuntime(unsigned int sourceLength);

namespace {

using zlib::CtData;
using zlib::DeflateState;
using zlib::GzHeaderW;
using zlib::StaticTreeDesc;
using zlib::TreeDesc;
using zlib::ZStream;

namespace zc = zlib;

// -----------------------------------------------------------------------------
// Small bit-buffer helpers. In the original these are the send_bits / send_code
// macros expanded inline into every trees.c function; the binary emitted them
// inline too, so the recovered bodies open-code the same two-branch shape. The
// helpers below capture the shared mechanics for the plain send_bits case; the
// tree walkers keep their own expansions because their divergent post-actions
// (updating a length register, etc.) are threaded through the branch.

// send_bits(s, value, length): accumulate `length` low bits of `value` into
// bi_buf, flushing a full 16-bit word to pending_buf when it overflows.
// Matches the trees.c send_bits macro and the two-arm shape in the .asm.
inline void SendBits(DeflateState* s, int value, int length)
{
  if (s->bi_valid > 16 - length)
  {
    s->bi_buf |= static_cast<std::uint16_t>(value << s->bi_valid);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf >> 8);
    s->bi_buf = static_cast<std::uint16_t>(static_cast<std::uint16_t>(value) >> (16 - s->bi_valid));
    s->bi_valid += length - 16;
  }
  else
  {
    s->bi_buf |= static_cast<std::uint16_t>(value << s->bi_valid);
    s->bi_valid += length;
  }
}

// send_code(s, node, tree): send the Huffman code for `node` from `tree`.
inline void SendCode(DeflateState* s, int node, const CtData* tree)
{
  SendBits(s, tree[node].Code(), tree[node].Len());
}

// -----------------------------------------------------------------------------
// TreeStoredBlock / CopyBlock / BiWindup / BiFlush / TreeAlign
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095F140 (FUN_0095F140)
 * Mangled: bi_windup
 *
 * Flush the bit buffer and align the output on a byte boundary. Writes the 1 or
 * 2 residual bytes of bi_buf into pending_buf, then clears bi_buf/bi_valid.
 */
void BiWindup(DeflateState* s)
{
  if (s->bi_valid > 8)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf >> 8);
  }
  else if (s->bi_valid > 0)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf);
  }
  s->bi_buf = 0;
  s->bi_valid = 0;
}

/**
 * Address: 0x0095F0C0 (FUN_0095F0C0 / sub_95F0C0)
 * Mangled: bi_flush
 *
 * Flush whole bytes out of the bit accumulator without byte-aligning (leaves a
 * partial bit residue). Emits two bytes when bi_valid==16, one byte when >=8.
 */
void BiFlush(DeflateState* s)
{
  if (s->bi_valid == 16)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf >> 8);
    s->bi_buf = 0;
    s->bi_valid = 0;
  }
  else if (s->bi_valid >= 8)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(s->bi_buf);
    s->bi_buf = static_cast<std::uint16_t>(s->bi_buf >> 8);
    s->bi_valid -= 8;
  }
}

/**
 * Address: 0x0095F1C0 (FUN_0095F1C0)
 * Mangled: copy_block
 *
 * Copy a stored block, byte-aligning first. When `header`, prepends the 16-bit
 * length and its one's-complement. IDA fastcall (len@ecx, buf@edx, header@stack)
 * with `s` recovered in eax from bi_windup's return; here `s` is the explicit
 * first parameter.
 */
void CopyBlock(DeflateState* s, const std::uint8_t* buf, unsigned int len, bool header)
{
  BiWindup(s);
  s->last_eob_len = 8;
  if (header)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(len);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(len >> 8);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(~len);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(~len >> 8);
  }
  while (len--)
  {
    s->pending_buf[s->pending++] = *buf++;
  }
}

/**
 * Address: 0x0095F620 (FUN_0095F620)
 * Mangled: _tr_stored_block
 *
 * Emit a stored block: send the STORED_BLOCK type header (3 bits: (0<<1)+last)
 * into the bit buffer, then copy_block the raw bytes with a length header.
 * IDA mangled the args; the real signature is
 * _tr_stored_block(s, buf, stored_len, last).
 */
void TreeStoredBlock(DeflateState* s, const std::uint8_t* buf,
                     unsigned int stored_len, int last)
{
  SendBits(s, last, 3);          // STORED_BLOCK<<1 | last  (STORED_BLOCK == 0)
  CopyBlock(s, buf, stored_len, /*header=*/true);
}

/**
 * Address: 0x0095F6C0 (FUN_0095F6C0)
 * Mangled: _tr_align
 *
 * Send one empty static block to give enough lookahead for inflate to decide the
 * following block is a stored block, used for Z_PARTIAL_FLUSH / Z_SYNC_FLUSH.
 * Sends STATIC_TREES<<1, the static EOB code, and (if <9 bits are left) another
 * empty static block.
 */
void TreeAlign(DeflateState* s)
{
  constexpr int kStaticTreesHeader = 1 << 1;  // STATIC_TREES(1) << 1, last == 0
  SendBits(s, kStaticTreesHeader, 3);
  SendCode(s, zc::kEndBlock, zc::kStaticLTree);
  BiFlush(s);
  // Of the 10 bits for the empty block, we have already sent length+eob code:
  // if there isn't enough room in bi_buf for another empty block, force it out.
  if (1 + s->last_eob_len + 10 - s->bi_valid < 9)
  {
    SendBits(s, kStaticTreesHeader, 3);
    SendCode(s, zc::kEndBlock, zc::kStaticLTree);
    BiFlush(s);
  }
  s->last_eob_len = 7;
}

// -----------------------------------------------------------------------------
// InitBlock / TreeInit / LmInit (reset-time tree state)
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095DF50 (FUN_0095DF50)
 * Mangled: init_block
 *
 * Zero the three tree frequency arrays, set the END_BLOCK literal to freq 1,
 * and clear the block accumulators (opt_len/static_len/matches/last_lit).
 */
void InitBlock(DeflateState* s)
{
  for (int n = 0; n < zc::kLCodes; ++n)  s->dyn_ltree[n].fc = 0;
  for (int n = 0; n < zc::kDCodes; ++n)  s->dyn_dtree[n].fc = 0;
  for (int n = 0; n < zc::kBlCodes; ++n) s->bl_tree[n].fc = 0;
  s->dyn_ltree[zc::kEndBlock].fc = 1;
  s->opt_len = 0;
  s->static_len = 0;
  s->matches = 0;
  s->last_lit = 0;
}

/**
 * Address: 0x0095F250 (FUN_0095F250)
 * Mangled: _tr_init
 *
 * Initialise the three tree descriptors (dyn_tree + stat_desc), clear the bit
 * buffer, set last_eob_len to 8, then init_block.
 */
void TreeInit(DeflateState* s)
{
  s->l_desc.dyn_tree = s->dyn_ltree;
  s->l_desc.stat_desc = &zc::kStaticLDesc;
  s->d_desc.dyn_tree = s->dyn_dtree;
  s->d_desc.stat_desc = &zc::kStaticDDesc;
  s->bl_desc.dyn_tree = s->bl_tree;
  s->bl_desc.stat_desc = &zc::kStaticBlDesc;
  s->bi_buf = 0;
  s->bi_valid = 0;
  s->last_eob_len = 8;
  InitBlock(s);
}

/**
 * Address: 0x0095B7D0 (FUN_0095B7D0)
 * Mangled: lm_init
 *
 * Initialise the "longest match" (LZ77) state: window_size = 2*w_size, clear the
 * hash heads, load the level's configuration_table entry into
 * max_lazy_match/good_match/nice_match/max_chain_length, reset the scan cursors.
 */
void LmInit(DeflateState* s)
{
  s->window_size = 2 * s->w_size;

  // CLEAR_HASH(s): head[hash_size-1] = NIL; memset head with zero for the rest.
  s->head[s->hash_size - 1] = 0;
  std::memset(s->head, 0, static_cast<std::size_t>(s->hash_size - 1) * sizeof(s->head[0]));

  const zc::DeflateConfig& cfg = zc::kConfigurationTable[s->level];
  s->max_lazy_match = cfg.max_lazy;
  s->good_match = cfg.good_length;
  s->nice_match = cfg.nice_length;
  s->max_chain_length = cfg.max_chain;

  s->strstart = 0;
  s->block_start = 0;
  s->lookahead = 0;
  s->match_length = zc::kMinMatch - 1;
  s->prev_length = zc::kMinMatch - 1;
  s->match_available = 0;
  s->ins_h = 0;
}

// -----------------------------------------------------------------------------
// Tree building: PqDownHeap / GenBitlen / GenCodes / BuildTree
// -----------------------------------------------------------------------------

// smaller(tree, n, m, depth): heap ordering predicate used by pqdownheap and
// build_tree — lower frequency, ties broken by shallower depth.
inline bool Smaller(const CtData* tree, int n, int m, const std::uint8_t* depth)
{
  return tree[n].Freq() < tree[m].Freq() ||
         (tree[n].Freq() == tree[m].Freq() && depth[n] <= depth[m]);
}

/**
 * Address: 0x0095DFC0 (FUN_0095DFC0)
 * Mangled: pqdownheap
 *
 * Restore the heap property by sinking heap[k] down, exchanging with the smaller
 * of its two sons (per the Smaller predicate). IDA passes tree via edi and s via
 * eax; here they are explicit parameters.
 */
void PqDownHeap(DeflateState* s, const CtData* tree, int k)
{
  const int v = s->heap[k];
  int j = k << 1;                 // left son
  while (j <= s->heap_len)
  {
    if (j < s->heap_len && Smaller(tree, s->heap[j + 1], s->heap[j], s->depth))
    {
      ++j;
    }
    if (Smaller(tree, v, s->heap[j], s->depth))
    {
      break;
    }
    s->heap[k] = s->heap[j];
    k = j;
    j <<= 1;
  }
  s->heap[k] = v;
}

/**
 * Address: 0x0095E090 (FUN_0095E090)
 * Mangled: gen_bitlen
 *
 * Compute the optimal bit lengths for a tree given the frequencies and depths
 * built by build_tree, honouring the max_length cap and redistributing overflow.
 * IDA passes s via eax and desc via ecx.
 */
void GenBitlen(DeflateState* s, const TreeDesc* desc)
{
  CtData* const tree = desc->dyn_tree;
  const int max_code = desc->max_code;
  const CtData* const stree = desc->stat_desc->static_tree;
  const int* const extra = desc->stat_desc->extra_bits;
  const int base = desc->stat_desc->extra_base;
  const int max_length = desc->stat_desc->max_length;
  int overflow = 0;

  for (int bits = 0; bits <= zc::kMaxBitsDeflate; ++bits)
  {
    s->bl_count[bits] = 0;
  }

  // The root has bit length 0 (heap_max holds the root of the tree).
  tree[s->heap[s->heap_max]].dl = 0;

  int h;
  for (h = s->heap_max + 1; h < zc::kHeapSize; ++h)
  {
    const int n = s->heap[h];
    int bits = tree[tree[n].Dad()].Len() + 1;
    if (bits > max_length)
    {
      bits = max_length;
      ++overflow;
    }
    tree[n].dl = static_cast<std::uint16_t>(bits);  // overwrite dad, now len

    if (n > max_code)
    {
      continue;  // not a leaf node
    }

    ++s->bl_count[bits];
    int xbits = 0;
    if (n >= base)
    {
      xbits = extra[n - base];
    }
    const std::uint16_t f = tree[n].Freq();
    s->opt_len += static_cast<unsigned int>(f) * static_cast<unsigned int>(bits + xbits);
    if (stree)
    {
      s->static_len +=
          static_cast<unsigned int>(f) *
          static_cast<unsigned int>(stree[n].Len() + xbits);
    }
  }

  if (overflow == 0)
  {
    return;
  }

  // Find the first bit length that could increase, and redistribute the overflow.
  do
  {
    int bits = max_length - 1;
    while (s->bl_count[bits] == 0)
    {
      --bits;
    }
    --s->bl_count[bits];        // move one leaf down the tree
    s->bl_count[bits + 1] += 2; // move one overflow item as its brother
    --s->bl_count[max_length];
    overflow -= 2;
  } while (overflow > 0);

  // Recompute all the codes' bit lengths, from the highest down.
  for (int bits = max_length; bits != 0; --bits)
  {
    int n = s->bl_count[bits];
    while (n != 0)
    {
      const int m = s->heap[--h];
      if (m > max_code)
      {
        continue;
      }
      if (tree[m].Len() != static_cast<std::uint16_t>(bits))
      {
        s->opt_len += static_cast<unsigned int>(
            (static_cast<int>(bits) - tree[m].Len()) * tree[m].Freq());
        tree[m].dl = static_cast<std::uint16_t>(bits);
      }
      --n;
    }
  }
}

/**
 * Address: 0x0095F2C0 (FUN_0095F2C0)
 * Mangled: gen_codes
 *
 * Assign the actual bit-reversed Huffman codes to each symbol given the bit
 * lengths computed by gen_bitlen and the per-length code counts in bl_count.
 * IDA passes tree via edi, max_code via ebx, bl_count via edx; here explicit.
 */
void GenCodes(CtData* tree, int max_code, const std::uint16_t* bl_count)
{
  std::uint16_t next_code[zc::kMaxBitsDeflate + 1] = {};
  std::uint16_t code = 0;

  // Distribute the base codes over the bit lengths.
  for (int bits = 1; bits <= zc::kMaxBitsDeflate; ++bits)
  {
    code = static_cast<std::uint16_t>((code + bl_count[bits - 1]) << 1);
    next_code[bits] = code;
  }

  for (int n = 0; n <= max_code; ++n)
  {
    const int len = tree[n].Len();
    if (len == 0)
    {
      continue;
    }
    // Reverse the bits of next_code[len] (bi_reverse).
    unsigned int res = 0;
    unsigned int c = next_code[len]++;
    for (int cnt = len; cnt > 0; --cnt)
    {
      res |= c & 1;
      c >>= 1;
      res <<= 1;
    }
    tree[n].fc = static_cast<std::uint16_t>(res >> 1);  // overwrite freq -> code
  }
}

/**
 * Address: 0x0095F350 (FUN_0095F350)
 * Mangled: build_tree
 *
 * Build one Huffman tree: construct the initial heap of leaves, build the tree
 * bottom-up by repeatedly combining the two least frequent nodes, then generate
 * the bit lengths and codes. IDA passes s via esi and desc via stack.
 */
void BuildTree(DeflateState* s, TreeDesc* desc)
{
  CtData* const tree = desc->dyn_tree;
  const CtData* const stree = desc->stat_desc->static_tree;
  const int elems = desc->stat_desc->elems;
  int max_code = -1;

  // Construct the initial heap; the least frequent element is at heap[SMALLEST].
  s->heap_len = 0;
  s->heap_max = zc::kHeapSize;
  for (int n = 0; n < elems; ++n)
  {
    if (tree[n].Freq() != 0)
    {
      s->heap[++s->heap_len] = max_code = n;
      s->depth[n] = 0;
    }
    else
    {
      tree[n].dl = 0;
    }
  }

  // Guarantee at least two codes exist, inventing them if necessary.
  while (s->heap_len < 2)
  {
    const int node = s->heap[++s->heap_len] = (max_code < 2) ? ++max_code : 0;
    tree[node].fc = 1;
    s->depth[node] = 0;
    --s->opt_len;
    if (stree)
    {
      s->static_len -= stree[node].Len();
    }
  }
  desc->max_code = max_code;

  // Establish the heap property, from the last internal node up.
  for (int n = s->heap_len / 2; n >= 1; --n)
  {
    PqDownHeap(s, tree, n);
  }

  // Combine the two least frequent nodes into a new internal node, repeatedly.
  int node = elems;
  do
  {
    // pqremove(): take heap[SMALLEST], move heap[heap_len--] to the top, sink it.
    const int n = s->heap[1 /*SMALLEST*/];
    s->heap[1] = s->heap[s->heap_len--];
    PqDownHeap(s, tree, 1);

    const int m = s->heap[1];       // m = next least frequent node

    s->heap[--s->heap_max] = n;     // keep the nodes sorted by frequency
    s->heap[--s->heap_max] = m;

    tree[node].fc = static_cast<std::uint16_t>(tree[n].Freq() + tree[m].Freq());
    s->depth[node] = static_cast<std::uint8_t>(
        (s->depth[n] >= s->depth[m] ? s->depth[n] : s->depth[m]) + 1);
    tree[n].dl = tree[m].dl = static_cast<std::uint16_t>(node);

    s->heap[1] = node++;
    PqDownHeap(s, tree, 1);
  } while (s->heap_len >= 2);

  s->heap[--s->heap_max] = s->heap[1];

  GenBitlen(s, desc);
  GenCodes(tree, max_code, s->bl_count);
}

// -----------------------------------------------------------------------------
// Bit-length tree building: ScanTree / SendTree / BuildBlTree / SendAllTrees
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095E2B0 (FUN_0095E2B0)
 * Mangled: scan_tree
 *
 * Scan a literal/distance tree to count the frequencies of the run-length codes
 * used to transmit its bit lengths (REP_3_6/REPZ_3_10/REPZ_11_138). IDA passes
 * tree via eax, max_code via ecx, s via stack.
 */
void ScanTree(DeflateState* s, CtData* tree, int max_code)
{
  int prevlen = -1;              // last emitted length
  int nextlen = tree[0].Len();   // length of next code
  int count = 0;                 // repeat count of the current code
  int max_count = 7;             // max repeat count
  int min_count = 4;             // min repeat count

  if (nextlen == 0)
  {
    max_count = 138;
    min_count = 3;
  }
  tree[max_code + 1].dl = 0xFFFF;  // guard

  for (int n = 0; n <= max_code; ++n)
  {
    const int curlen = nextlen;
    nextlen = tree[n + 1].Len();
    if (++count < max_count && curlen == nextlen)
    {
      continue;
    }
    if (count < min_count)
    {
      s->bl_tree[curlen].fc += static_cast<std::uint16_t>(count);
    }
    else if (curlen != 0)
    {
      if (curlen != prevlen)
      {
        ++s->bl_tree[curlen].fc;
      }
      ++s->bl_tree[zc::kRep_3_6].fc;
    }
    else if (count <= 10)
    {
      ++s->bl_tree[zc::kRepz_3_10].fc;
    }
    else
    {
      ++s->bl_tree[zc::kRepz_11_138].fc;
    }

    count = 0;
    prevlen = curlen;
    if (nextlen == 0)
    {
      max_count = 138;
      min_count = 3;
    }
    else if (curlen == nextlen)
    {
      max_count = 6;
      min_count = 3;
    }
    else
    {
      max_count = 7;
      min_count = 4;
    }
  }
}

/**
 * Address: 0x0095E3A0 (FUN_0095E3A0)
 * Mangled: send_tree
 *
 * Send a literal/distance tree in compressed form, using the bit-length tree and
 * the run-length codes. IDA passes s via eax, tree via edx, max_code via ecx.
 */
void SendTree(DeflateState* s, CtData* tree, int max_code)
{
  int prevlen = -1;
  int nextlen = tree[0].Len();
  int count = 0;
  int max_count = 7;
  int min_count = 4;

  if (nextlen == 0)
  {
    max_count = 138;
    min_count = 3;
  }

  for (int n = 0; n <= max_code; ++n)
  {
    const int curlen = nextlen;
    nextlen = tree[n + 1].Len();
    if (++count < max_count && curlen == nextlen)
    {
      continue;
    }
    if (count < min_count)
    {
      do
      {
        SendCode(s, curlen, s->bl_tree);
      } while (--count != 0);
    }
    else if (curlen != 0)
    {
      if (curlen != prevlen)
      {
        SendCode(s, curlen, s->bl_tree);
        --count;
      }
      SendCode(s, zc::kRep_3_6, s->bl_tree);
      SendBits(s, count - 3, 2);
    }
    else if (count <= 10)
    {
      SendCode(s, zc::kRepz_3_10, s->bl_tree);
      SendBits(s, count - 3, 3);
    }
    else
    {
      SendCode(s, zc::kRepz_11_138, s->bl_tree);
      SendBits(s, count - 11, 7);
    }

    count = 0;
    prevlen = curlen;
    if (nextlen == 0)
    {
      max_count = 138;
      min_count = 3;
    }
    else if (curlen == nextlen)
    {
      max_count = 6;
      min_count = 3;
    }
    else
    {
      max_count = 7;
      min_count = 4;
    }
  }
}

/**
 * Address: 0x0095F550 (FUN_0095F550)
 * Mangled: build_bl_tree
 *
 * Build the bit-length tree that describes how the literal and distance trees'
 * bit lengths are transmitted, and return the index of the last bit-length code
 * that must be sent. IDA passes s via eax.
 */
int BuildBlTree(DeflateState* s)
{
  ScanTree(s, s->dyn_ltree, s->l_desc.max_code);
  ScanTree(s, s->dyn_dtree, s->d_desc.max_code);
  BuildTree(s, &s->bl_desc);

  // Determine the number of bit-length codes to send (drop trailing zeros).
  int max_blindex;
  for (max_blindex = zc::kBlCodes - 1; max_blindex >= 3; --max_blindex)
  {
    if (s->bl_tree[zc::kBlOrder[max_blindex]].Dad() != 0)
    {
      break;
    }
  }
  s->opt_len += 3 * (max_blindex + 1) + 5 + 5 + 4;
  return max_blindex;
}

/**
 * Address: 0x0095E8C0 (FUN_0095E8C0)
 * Mangled: send_all_trees
 *
 * Send the header (5+5+4 bits of code counts), the bit-length tree, then the
 * literal and distance trees. IDA passes s via eax; lcodes/dcodes/blcodes stack.
 */
void SendAllTrees(DeflateState* s, int lcodes, int dcodes, int blcodes)
{
  SendBits(s, lcodes - 257, 5);
  SendBits(s, dcodes - 1, 5);
  SendBits(s, blcodes - 4, 4);
  for (int rank = 0; rank < blcodes; ++rank)
  {
    SendBits(s, s->bl_tree[zc::kBlOrder[rank]].Dad(), 3);
  }
  SendTree(s, s->dyn_ltree, lcodes - 1);
  SendTree(s, s->dyn_dtree, dcodes - 1);
}

/**
 * Address: 0x0095EBC0 (FUN_0095EBC0)
 * Mangled: compress_block
 *
 * Send the current block of literal/length + distance pairs stored in
 * l_buf/d_buf using the given literal (ltree) and distance (dtree) trees. IDA
 * passes s via eax; ltree/dtree via stack.
 */
void CompressBlock(DeflateState* s, const CtData* ltree, const CtData* dtree)
{
  if (s->last_lit != 0)
  {
    unsigned int lx = 0;
    do
    {
      unsigned int dist = s->d_buf[lx];
      int lc = s->l_buf[lx];
      ++lx;
      if (dist == 0)
      {
        SendCode(s, lc, ltree);  // literal byte
      }
      else
      {
        // Send the length code + its extra bits.
        int code = zc::kLengthCode[lc];
        SendCode(s, code + zc::kLiterals + 1, ltree);
        int extra = zc::kExtraLBits[code];
        if (extra != 0)
        {
          lc -= zc::kBaseLength[code];
          SendBits(s, lc, extra);
        }
        // Send the distance code + its extra bits.
        --dist;
        code = (dist < 256) ? zc::kDistCode[dist] : zc::kDistCode[256 + (dist >> 7)];
        SendCode(s, code, dtree);
        extra = zc::kExtraDBits[code];
        if (extra != 0)
        {
          dist -= static_cast<unsigned int>(zc::kBaseDist[code]);
          SendBits(s, static_cast<int>(dist), extra);
        }
      }
    } while (lx < s->last_lit);
  }
  SendCode(s, zc::kEndBlock, ltree);
  s->last_eob_len = ltree[zc::kEndBlock].Len();
}

/**
 * Address: 0x0095EFD0 (FUN_0095EFD0)
 * Mangled: set_data_type
 *
 * Guess whether the data is binary or text by looking at the literal frequency
 * table: text if any of the block-list "text" characters appear and none of the
 * black-listed control characters do. IDA passes s via edx.
 */
void SetDataType(DeflateState* s)
{
  // The 0x00..0x08, 0x0E..0x1F control block-list uses a bitmask in stock zlib;
  // this build open-codes the scan. n counts up while examining the tree in the
  // exact order the .asm walks it (literals 0..8, then 14,20,...,31, +6 stride).
  int n = 0;
  while (n < 9)
  {
    if (s->dyn_ltree[n].Freq() != 0)
    {
      break;
    }
    ++n;
  }
  if (n == 9)
  {
    // None of the first control chars present; scan the 14..31 band.
    n = 14;
    for (int idx = 14; idx < 32; idx += 6)
    {
      if (s->dyn_ltree[idx - 1].Freq() != 0)
      {
        break;
      }
      if (s->dyn_ltree[idx].Freq() != 0)     { n = idx + 0; break; }
      if (s->dyn_ltree[idx + 1].Freq() != 0) { n = idx + 1; break; }
      if (s->dyn_ltree[idx + 2].Freq() != 0) { n = idx + 2; break; }
      if (s->dyn_ltree[idx + 3].Freq() != 0) { n = idx + 3; break; }
      if (s->dyn_ltree[idx + 4].Freq() != 0) { n = idx + 4; break; }
      n = idx + 6;
    }
  }
  reinterpret_cast<ZStream*>(s->strm)->data_type = (n == 32) ? 1 : 0;  // Z_BINARY:Z_TEXT
}

/**
 * Address: 0x0095F8B0 (FUN_0095F8B0)
 * Mangled: _tr_flush_block
 *
 * Determine the best encoding for the current block (stored / static / dynamic),
 * emit its header + contents, and re-initialise the block state.
 * _tr_flush_block(s, buf, stored_len, last).
 */
void TreeFlushBlock(DeflateState* s, const std::uint8_t* buf,
                    unsigned int stored_len, int last)
{
  unsigned int opt_lenb;
  unsigned int static_lenb;
  int max_blindex = 0;

  if (s->level > 0)
  {
    if (stored_len > 0 &&
        reinterpret_cast<ZStream*>(s->strm)->data_type == 2 /*Z_UNKNOWN*/)
    {
      SetDataType(s);
    }
    BuildTree(s, &s->l_desc);
    BuildTree(s, &s->d_desc);
    max_blindex = BuildBlTree(s);

    opt_lenb = (s->opt_len + 3 + 7) >> 3;
    static_lenb = (s->static_len + 3 + 7) >> 3;
    if (static_lenb <= opt_lenb)
    {
      opt_lenb = static_lenb;
    }
  }
  else
  {
    // level == 0: force a stored block.
    opt_lenb = static_lenb = stored_len + 5;
  }

  if (stored_len + 4 <= opt_lenb && buf != nullptr)
  {
    // A stored block is smaller (or forced): emit it raw.
    TreeStoredBlock(s, buf, stored_len, last);
  }
  else if (s->strategy == zc::kZFixed || static_lenb == opt_lenb)
  {
    SendBits(s, (1 /*STATIC_TREES*/ << 1) + last, 3);
    CompressBlock(s, zc::kStaticLTree, zc::kStaticDTree);
  }
  else
  {
    SendBits(s, (2 /*DYN_TREES*/ << 1) + last, 3);
    SendAllTrees(s, s->l_desc.max_code + 1, s->d_desc.max_code + 1, max_blindex + 1);
    CompressBlock(s, s->dyn_ltree, s->dyn_dtree);
  }

  InitBlock(s);
  if (last)
  {
    BiWindup(s);
  }
}

// -----------------------------------------------------------------------------
// ReadBuf / FillWindow / LongestMatch / LongestMatchFast
// -----------------------------------------------------------------------------

/**
 * read_buf: copy up to `size` bytes from the input into `buf`, updating the
 * running checksum according to wrap. This is inlined into fill_window in the
 * binary (it calls adler32/crc32 directly at 0x0095BB84/0x0095BB98) rather than
 * emitted as a standalone body; recovered here as a helper the callers name.
 */
unsigned int ReadBuf(ZStream* strm, std::uint8_t* buf, unsigned int size)
{
  unsigned int len = strm->avail_in;
  if (len > size)
  {
    len = size;
  }
  if (len == 0)
  {
    return 0;
  }
  strm->avail_in -= len;

  DeflateState* const s = static_cast<DeflateState*>(strm->state);
  if (s->wrap == 1)
  {
    strm->adler = adler32(strm->adler, strm->next_in, len);
  }
  else if (s->wrap == 2)
  {
    strm->adler = crc32(strm->adler, strm->next_in, len);
  }
  std::memcpy(buf, strm->next_in, len);
  strm->next_in += len;
  strm->total_in += len;
  return len;
}

/**
 * Address: 0x0095BAB0 (FUN_0095BAB0)
 * Mangled: fill_window
 *
 * Read more input into the window, sliding the window down and re-basing the
 * hash/prev tables when the read cursor reaches the far end. IDA passes s via
 * esi. Loops until MIN_LOOKAHEAD bytes are available or input is exhausted.
 */
void FillWindow(DeflateState* s)
{
  const unsigned int wsize = s->w_size;
  unsigned int more;

  do
  {
    more = s->window_size - s->lookahead - s->strstart;

    // If the window is (almost) full and the read cursor is deep enough, slide.
    if (s->strstart >= wsize + (wsize - zc::kMinLookahead))
    {
      std::memcpy(s->window, s->window + wsize, wsize);
      s->match_start -= wsize;
      s->strstart -= wsize;
      s->block_start -= static_cast<int>(wsize);

      // Slide the hash table (Wclear-style; each entry >= wsize is rebased).
      unsigned int n = s->hash_size;
      std::uint16_t* p = s->head + n;
      do
      {
        const unsigned int m = *--p;
        *p = (m < wsize) ? 0 : static_cast<std::uint16_t>(m - wsize);
      } while (--n);

      n = wsize;
      p = s->prev + n;
      do
      {
        const unsigned int m = *--p;
        *p = (m < wsize) ? 0 : static_cast<std::uint16_t>(m - wsize);
      } while (--n);

      more += wsize;
    }

    if (reinterpret_cast<ZStream*>(s->strm)->avail_in == 0)
    {
      break;
    }

    const unsigned int n = ReadBuf(reinterpret_cast<ZStream*>(s->strm),
                                   s->window + s->strstart + s->lookahead, more);
    s->lookahead += n;

    // Initialise the hash of the string that just became complete.
    if (s->lookahead >= zc::kMinMatch)
    {
      const std::uint8_t* w = s->window + s->strstart;
      s->ins_h = w[0];
      s->ins_h = ((s->ins_h << s->hash_shift) ^ w[1]) & s->hash_mask;
    }
  } while (s->lookahead < zc::kMinLookahead &&
           reinterpret_cast<ZStream*>(s->strm)->avail_in != 0);
}

/**
 * Address: 0x0095B860 (FUN_0095B860)
 * Mangled: longest_match
 *
 * Find the longest match for the string at strstart in the window, following the
 * hash chain from cur_match. Returns the match length (<= lookahead). The 8-way
 * unrolled compare and the two-byte "scan_end" guard match the .asm exactly.
 * IDA passes cur_match via eax, s via edi.
 */
unsigned int LongestMatch(DeflateState* s, unsigned int cur_match)
{
  unsigned int chain_length = s->max_chain_length;
  const std::uint8_t* scan = s->window + s->strstart;
  const std::uint8_t* match;
  int len;
  int best_len = static_cast<int>(s->prev_length);
  int nice_match = s->nice_match;
  const unsigned int limit =
      s->strstart > (s->w_size - zc::kMinLookahead)
          ? s->strstart - (s->w_size - zc::kMinLookahead)
          : 0;
  const std::uint16_t* const prev = s->prev;
  const unsigned int wmask = s->w_mask;

  const std::uint8_t* const strend = s->window + s->strstart + zc::kMaxMatch;
  std::uint8_t scan_end1 = scan[best_len - 1];
  std::uint8_t scan_end = scan[best_len];

  // Do not waste too much time if we already have a good match.
  if (s->prev_length >= s->good_match)
  {
    chain_length >>= 2;
  }
  if (static_cast<unsigned int>(nice_match) > s->lookahead)
  {
    nice_match = static_cast<int>(s->lookahead);
  }

  do
  {
    match = s->window + cur_match;

    // Skip if it does not extend the current best match.
    if (match[best_len] != scan_end || match[best_len - 1] != scan_end1 ||
        *match != *scan || *++match != scan[1])
    {
      cur_match = prev[cur_match & wmask];
      if (cur_match <= limit)
      {
        break;
      }
      continue;
    }

    // The two starting bytes match; step forward comparing 8 at a time.
    scan += 2;
    ++match;
    do
    {
    } while (*++scan == *++match && *++scan == *++match &&
             *++scan == *++match && *++scan == *++match &&
             *++scan == *++match && *++scan == *++match &&
             *++scan == *++match && *++scan == *++match && scan < strend);

    len = zc::kMaxMatch - static_cast<int>(strend - scan);
    scan = strend - zc::kMaxMatch;

    if (len > best_len)
    {
      s->match_start = cur_match;
      best_len = len;
      if (len >= nice_match)
      {
        break;
      }
      scan_end1 = scan[best_len - 1];
      scan_end = scan[best_len];
    }

    cur_match = prev[cur_match & wmask];
    if (cur_match <= limit)
    {
      break;
    }
  } while (--chain_length != 0);

  if (static_cast<unsigned int>(best_len) <= s->lookahead)
  {
    return static_cast<unsigned int>(best_len);
  }
  return s->lookahead;
}

/**
 * Address: 0x0095B9E0 (FUN_0095B9E0)
 * Mangled: longest_match_fast
 *
 * The FASTEST-strategy (Z_RLE) match: only checks the single candidate at
 * cur_match with the same 8-way unrolled compare, no chain walk. IDA passes s
 * via esi, cur_match via stack.
 */
unsigned int LongestMatchFast(DeflateState* s, unsigned int cur_match)
{
  std::uint8_t* const scan0 = s->window + s->strstart;
  std::uint8_t* const match0 = s->window + cur_match;
  const std::uint8_t* const strend = match0 + zc::kMaxMatch;

  if (scan0[0] != match0[0] || scan0[1] != match0[1])
  {
    return zc::kMinMatch - 1;
  }

  const std::uint8_t* match = match0 + 1;
  const std::uint8_t* scan = scan0 + 1;
  do
  {
  } while (*++match == *++scan && *++match == *++scan &&
           *++match == *++scan && *++match == *++scan &&
           *++match == *++scan && *++match == *++scan &&
           *++match == *++scan && *++match == *++scan && match < strend);

  const int len = zc::kMaxMatch - static_cast<int>(strend - match);
  if (len < zc::kMinMatch)
  {
    return zc::kMinMatch - 1;
  }
  s->match_start = cur_match;
  if (static_cast<unsigned int>(len) > s->lookahead)
  {
    return s->lookahead;
  }
  return static_cast<unsigned int>(len);
}

// -----------------------------------------------------------------------------
// FlushPending / PutShortMSB (driver output helpers)
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095ACB0 (FUN_0095ACB0)
 * Mangled: flush_pending
 *
 * Copy as many pending output bytes as fit into the caller's output buffer and
 * advance the stream counters. IDA passes strm via eax.
 */
void FlushPending(ZStream* strm)
{
  DeflateState* const s = static_cast<DeflateState*>(strm->state);
  unsigned int len = s->pending;
  if (len > strm->avail_out)
  {
    len = strm->avail_out;
  }
  if (len == 0)
  {
    return;
  }

  std::memcpy(strm->next_out, s->pending_out, len);
  strm->next_out += len;
  s->pending_out += len;
  strm->total_out += len;
  strm->avail_out -= len;
  s->pending -= len;
  if (s->pending == 0)
  {
    s->pending_out = s->pending_buf;
  }
}

/**
 * Address: 0x0095AC80 (FUN_0095AC80)
 * Mangled: putShortMSB
 *
 * Write a 16-bit value into pending_buf most-significant byte first. IDA passes
 * s via eax, b via cx, returns s.
 */
void PutShortMSB(DeflateState* s, unsigned int b)
{
  s->pending_buf[s->pending++] = static_cast<std::uint8_t>(b >> 8);
  s->pending_buf[s->pending++] = static_cast<std::uint8_t>(b);
}

// -----------------------------------------------------------------------------
// The three block compressors: DeflateStored / DeflateFast / DeflateSlow
// -----------------------------------------------------------------------------

// FLUSH_BLOCK_ONLY(s, last): flush the current block (window[block_start..
// strstart)) and copy the pending output out. Returns true if the output buffer
// filled up (caller must return need_more). This is the FLUSH_BLOCK_ONLY macro
// from deflate.c, inlined into each compressor in the binary.
bool FlushBlockOnly(DeflateState* s, int last)
{
  TreeFlushBlock(s, s->block_start >= 0 ? s->window + s->block_start : nullptr,
                 s->strstart - static_cast<unsigned int>(s->block_start), last);
  s->block_start = static_cast<int>(s->strstart);
  FlushPending(reinterpret_cast<ZStream*>(s->strm));
  return reinterpret_cast<ZStream*>(s->strm)->avail_out == 0;
}

// INSERT_STRING(s, str, match_head): update the hash of the string starting at
// str, insert it into the hash chain, set match_head to the previous head.
inline unsigned int InsertString(DeflateState* s, unsigned int str)
{
  s->ins_h = ((s->ins_h << s->hash_shift) ^ s->window[str + (zc::kMinMatch - 1)]) & s->hash_mask;
  const unsigned int match_head = s->prev[str & s->w_mask] = s->head[s->ins_h];
  s->head[s->ins_h] = static_cast<std::uint16_t>(str);
  return match_head;
}

/**
 * Address: 0x0095BC00 (FUN_0095BC00)
 * Mangled: deflate_stored
 *
 * The level-0 compressor: copy input verbatim into stored blocks, never using
 * the window's match machinery beyond keeping enough lookahead. Returns a
 * block_state. IDA passes s via eax; flush via stack.
 */
zc::BlockState DeflateStored(DeflateState* s, int flush)
{
  unsigned int max_block_size = 0xFFFF;
  if (max_block_size > s->pending_buf_size - 5)
  {
    max_block_size = s->pending_buf_size - 5;
  }

  for (;;)
  {
    // Fill the window as much as possible.
    if (s->lookahead <= 1)
    {
      FillWindow(s);
      if (s->lookahead == 0 && flush == zc::kDeflateNoFlush)
      {
        return zc::kBlockNeedMore;
      }
      if (s->lookahead == 0)
      {
        break;  // flush the current block
      }
    }

    s->strstart += s->lookahead;
    s->lookahead = 0;

    // Emit the block if it has grown past max_block_size.
    const unsigned int max_start = static_cast<unsigned int>(s->block_start) + max_block_size;
    if (s->strstart == 0 || s->strstart >= max_start)
    {
      // Strstart == 0 is possible when wraparound on 16-bit machine.
      s->lookahead = s->strstart - max_start;
      s->strstart = max_start;
      if (FlushBlockOnly(s, 0))
      {
        return zc::kBlockNeedMore;
      }
    }

    // Flush if the window is at least half full to keep it from filling.
    if (s->strstart - static_cast<unsigned int>(s->block_start) >=
        s->w_size - zc::kMinLookahead)
    {
      if (FlushBlockOnly(s, 0))
      {
        return zc::kBlockNeedMore;
      }
    }
  }

  if (flush == zc::kDeflateNoFlush)
  {
    return zc::kBlockNeedMore;
  }
  if (FlushBlockOnly(s, flush == zc::kDeflateFinish))
  {
    return flush == zc::kDeflateFinish ? zc::kBlockFinishStarted : zc::kBlockNeedMore;
  }
  return flush == zc::kDeflateFinish ? zc::kBlockFinishDone : zc::kBlockDone;
}

/**
 * Address: 0x0095BDE0 (FUN_0095BDE0)
 * Mangled: deflate_fast
 *
 * The fast compressor (levels 1..3): a single-pass greedy matcher with no lazy
 * evaluation. Returns a block_state. IDA passes s via stack; flush via stack.
 */
zc::BlockState DeflateFast(DeflateState* s, int flush)
{
  unsigned int hash_head = 0;   // head of the hash chain

  for (;;)
  {
    // Make sure we always have MIN_LOOKAHEAD bytes ahead.
    if (s->lookahead < zc::kMinLookahead)
    {
      FillWindow(s);
      if (s->lookahead < zc::kMinLookahead && flush == zc::kDeflateNoFlush)
      {
        return zc::kBlockNeedMore;
      }
      if (s->lookahead == 0)
      {
        break;
      }
    }

    // Insert the string window[strstart .. strstart+2] into the hash table.
    if (s->lookahead >= zc::kMinMatch)
    {
      hash_head = InsertString(s, s->strstart);
    }

    // Find the longest match; length capped by lookahead / MAX_DIST.
    if (hash_head != 0 &&
        s->strstart - hash_head <= s->w_size - zc::kMinLookahead)
    {
      if (s->strategy != zc::kZHuffmanOnly)
      {
        if (s->strategy == zc::kZRle)
        {
          if (s->strstart - hash_head == 1)
          {
            s->match_length = LongestMatchFast(s, hash_head);
          }
        }
        else
        {
          s->match_length = LongestMatch(s, hash_head);
        }
      }
    }

    bool flush_now;
    if (s->match_length >= zc::kMinMatch)
    {
      // _tr_tally_dist(s, strstart-match_start, match_length-MIN_MATCH, flush).
      const unsigned int dist = s->strstart - s->match_start;
      const std::uint8_t lc = static_cast<std::uint8_t>(s->match_length - zc::kMinMatch);
      s->d_buf[s->last_lit] = static_cast<std::uint16_t>(dist);
      s->l_buf[s->last_lit++] = lc;
      ++s->dyn_ltree[zc::kLengthCode[lc] + zc::kLiterals + 1].fc;
      const unsigned int d = dist - 1;
      ++s->dyn_dtree[(d < 256) ? zc::kDistCode[d] : zc::kDistCode[256 + (d >> 7)]].fc;
      flush_now = (s->last_lit == s->lit_bufsize - 1);

      s->lookahead -= s->match_length;

      // Insert new strings in the hash table only if the match is not too long.
      if (s->match_length <= s->max_lazy_match && s->lookahead >= zc::kMinMatch)
      {
        --s->match_length;
        do
        {
          ++s->strstart;
          hash_head = InsertString(s, s->strstart);
        } while (--s->match_length != 0);
        ++s->strstart;
      }
      else
      {
        s->strstart += s->match_length;
        s->match_length = 0;
        s->ins_h = s->window[s->strstart];
        s->ins_h = ((s->ins_h << s->hash_shift) ^ s->window[s->strstart + 1]) & s->hash_mask;
      }
    }
    else
    {
      // No match; output a literal byte.
      const std::uint8_t lc = s->window[s->strstart];
      s->d_buf[s->last_lit] = 0;
      s->l_buf[s->last_lit++] = lc;
      ++s->dyn_ltree[lc].fc;
      flush_now = (s->last_lit == s->lit_bufsize - 1);
      --s->lookahead;
      ++s->strstart;
    }

    if (flush_now)
    {
      if (FlushBlockOnly(s, 0))
      {
        return zc::kBlockNeedMore;
      }
    }
  }

  if (FlushBlockOnly(s, flush == zc::kDeflateFinish))
  {
    return flush == zc::kDeflateFinish ? zc::kBlockFinishStarted : zc::kBlockNeedMore;
  }
  return flush == zc::kDeflateFinish ? zc::kBlockFinishDone : zc::kBlockDone;
}

/**
 * Address: 0x0095C150 (FUN_0095C150)
 * Mangled: deflate_slow
 *
 * The slow compressor (levels 4..9): lazy matching — evaluate the match at the
 * next position before committing the current one. Returns a block_state. IDA
 * passes s via stack; flush via stack.
 */
zc::BlockState DeflateSlow(DeflateState* s, int flush)
{
  unsigned int hash_head = 0;

  for (;;)
  {
    if (s->lookahead < zc::kMinLookahead)
    {
      FillWindow(s);
      if (s->lookahead < zc::kMinLookahead && flush == zc::kDeflateNoFlush)
      {
        return zc::kBlockNeedMore;
      }
      if (s->lookahead == 0)
      {
        break;
      }
    }

    if (s->lookahead >= zc::kMinMatch)
    {
      hash_head = InsertString(s, s->strstart);
    }

    // Save the current match as the "previous" match, then look for a new one.
    s->prev_length = s->match_length;
    s->prev_match = s->match_start;
    s->match_length = zc::kMinMatch - 1;

    if (hash_head != 0 && s->prev_length < s->max_lazy_match &&
        s->strstart - hash_head <= s->w_size - zc::kMinLookahead)
    {
      if (s->strategy != zc::kZHuffmanOnly)
      {
        if (s->strategy == zc::kZRle)
        {
          if (s->strstart - hash_head == 1)
          {
            s->match_length = LongestMatchFast(s, hash_head);
          }
        }
        else
        {
          s->match_length = LongestMatch(s, hash_head);
        }
      }
      // Ignore a length-3 match if it is too distant, or a filtered short match.
      if (s->match_length <= 5 &&
          (s->strategy == zc::kZFiltered ||
           (s->match_length == zc::kMinMatch && s->strstart - s->match_start > 4096)))
      {
        s->match_length = zc::kMinMatch - 1;
      }
    }

    // If there was a match at the previous step and the current is not better,
    // emit the previous match.
    if (s->prev_length >= zc::kMinMatch && s->match_length <= s->prev_length)
    {
      const unsigned int max_insert = s->strstart + s->lookahead - zc::kMinMatch;
      const std::uint8_t lc = static_cast<std::uint8_t>(s->prev_length - zc::kMinMatch);
      const unsigned int dist = s->strstart - 1 - s->prev_match;
      s->d_buf[s->last_lit] = static_cast<std::uint16_t>(dist);
      s->l_buf[s->last_lit++] = lc;
      ++s->dyn_ltree[zc::kLengthCode[lc] + zc::kLiterals + 1].fc;
      const unsigned int d = dist - 1;
      ++s->dyn_dtree[(d < zc::kLiterals) ? zc::kDistCode[d] : zc::kDistCode[256 + (d >> 7)]].fc;
      const bool flush_now = (s->last_lit == s->lit_bufsize - 1);

      s->lookahead -= s->prev_length - 1;
      s->prev_length -= 2;
      do
      {
        if (++s->strstart <= max_insert)
        {
          hash_head = InsertString(s, s->strstart);
        }
      } while (--s->prev_length != 0);
      s->match_available = 0;
      s->match_length = zc::kMinMatch - 1;
      ++s->strstart;

      if (flush_now)
      {
        if (FlushBlockOnly(s, 0))
        {
          return zc::kBlockNeedMore;
        }
      }
    }
    else if (s->match_available)
    {
      // No match at the previous position; output the single deferred literal.
      const std::uint8_t lc = s->window[s->strstart - 1];
      s->d_buf[s->last_lit] = 0;
      s->l_buf[s->last_lit++] = lc;
      ++s->dyn_ltree[lc].fc;
      if (s->last_lit == s->lit_bufsize - 1)
      {
        // FLUSH_BLOCK_ONLY inlined; note it happens BEFORE strstart/lookahead
        // advance here (matches the .asm order at 0x0095C43A..0x0095C50C).
        FlushBlockOnly(s, 0);
      }
      ++s->strstart;
      --s->lookahead;
      if (reinterpret_cast<ZStream*>(s->strm)->avail_out == 0)
      {
        return zc::kBlockNeedMore;
      }
    }
    else
    {
      // No match yet; defer the literal and continue.
      s->match_available = 1;
      ++s->strstart;
      --s->lookahead;
    }
  }

  if (s->match_available)
  {
    const std::uint8_t lc = s->window[s->strstart - 1];
    s->d_buf[s->last_lit] = 0;
    s->l_buf[s->last_lit++] = lc;
    ++s->dyn_ltree[lc].fc;
    s->match_available = 0;
  }

  if (FlushBlockOnly(s, flush == zc::kDeflateFinish))
  {
    return flush == zc::kDeflateFinish ? zc::kBlockFinishStarted : zc::kBlockNeedMore;
  }
  return flush == zc::kDeflateFinish ? zc::kBlockFinishDone : zc::kBlockDone;
}

// Dispatch the block compressor for a given level (configuration_table[level]
// .func in the binary: L0 stored, L1..3 fast, L4..9 slow).
zc::BlockState CompressByLevel(DeflateState* s, int level, int flush)
{
  if (level == 0)
  {
    return DeflateStored(s, flush);
  }
  if (level <= 3)
  {
    return DeflateFast(s, flush);
  }
  return DeflateSlow(s, flush);
}

}  // namespace

// -----------------------------------------------------------------------------
// Public zlib API
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095C5E0 (FUN_0095C5E0)
 * Mangled: deflateReset
 *
 * IDA signature:
 * int __cdecl deflateReset(z_streamp strm);
 *
 * Reset a deflate stream to the start of a new compression: zero the counters,
 * set the initial status (INIT/BUSY by wrap), initialise the checksum, and reset
 * the tree + LZ77 state via tr_init/lm_init.
 */
extern "C" int deflateReset(ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr)
  {
    return kZStreamError;
  }
  auto* const s = static_cast<DeflateState*>(strm->state);
  if (s == nullptr || strm->zalloc == nullptr || strm->zfree == nullptr)
  {
    return kZStreamError;
  }

  strm->total_in = 0;
  strm->total_out = 0;
  strm->msg = nullptr;
  strm->data_type = 2;  // Z_UNKNOWN

  s->pending = 0;
  s->pending_out = s->pending_buf;

  if (s->wrap < 0)
  {
    s->wrap = -s->wrap;  // was made negative by a Z_FINISH deflate()
  }
  s->status = (s->wrap != 0) ? kDeflateInitState : kDeflateBusyState;
  strm->adler = (s->wrap == 2) ? crc32(0, nullptr, 0) : adler32(0, nullptr, 0);
  s->last_flush = 0;

  TreeInit(s);
  LmInit(s);
  return kZOk;
}

/**
 * Address: 0x0095C740 (FUN_0095C740)
 * Mangled: deflateInit2_
 *
 * IDA signature:
 * int __cdecl deflateInit2_(z_streamp strm, int level, int method, int windowBits,
 *                           int memLevel, int strategy, const char* version,
 *                           int stream_size);
 *
 * Allocate and initialise a deflate_state: validate the parameters, ZALLOC the
 * 0x16C0-byte state plus the window/prev/head/pending_buf buffers, set the
 * window/hash geometry and the lit/dist buffers, then deflateReset. Returns
 * Z_OK, Z_STREAM_ERROR, Z_MEM_ERROR or Z_VERSION_ERROR.
 */
extern "C" int deflateInit2_(ZStream* strm, int level, int method, int windowBits,
                             int memLevel, int strategy, const char* version,
                             int stream_size)
{
  using namespace zlib;

  int wrap = 1;
  if (version == nullptr || version[0] != '1' || stream_size != static_cast<int>(sizeof(ZStream)))
  {
    return kZVersionError;
  }
  if (strm == nullptr)
  {
    return kZStreamError;
  }

  strm->msg = nullptr;
  if (strm->zalloc == nullptr)
  {
    strm->zalloc = reinterpret_cast<void*>(&zcalloc);
    strm->opaque = nullptr;
  }
  if (strm->zfree == nullptr)
  {
    strm->zfree = reinterpret_cast<void*>(&zcfree);
  }

  if (level == kZDefaultCompression)
  {
    level = 6;
  }

  if (windowBits < 0)
  {
    wrap = 0;                 // suppress zlib wrapper
    windowBits = -windowBits;
  }
  else if (windowBits > 15)
  {
    wrap = 2;                 // write gzip wrapper
    windowBits -= 16;
  }

  if (memLevel < 1 || memLevel > 9 || method != kZDeflated ||
      windowBits < 8 || windowBits > 15 || level < 0 || level > kZBestCompression ||
      strategy > kZFixed)
  {
    return kZStreamError;
  }
  if (windowBits == 8)
  {
    windowBits = 9;           // until 256-byte window bug fixed
  }

  const auto zalloc = reinterpret_cast<AllocFunc>(strm->zalloc);
  auto* const s = static_cast<DeflateState*>(zalloc(strm->opaque, 1, sizeof(DeflateState)));
  if (s == nullptr)
  {
    return kZMemError;
  }
  strm->state = s;
  s->strm = strm;

  s->wrap = wrap;
  s->gzhead = nullptr;
  s->w_bits = static_cast<unsigned int>(windowBits);
  s->w_size = 1u << s->w_bits;
  s->w_mask = s->w_size - 1;

  s->hash_bits = static_cast<unsigned int>(memLevel) + 7;
  s->hash_size = 1u << s->hash_bits;
  s->hash_mask = s->hash_size - 1;
  s->hash_shift = (s->hash_bits + kMinMatch - 1) / kMinMatch;

  s->window = static_cast<std::uint8_t*>(zalloc(strm->opaque, s->w_size, 2 * sizeof(std::uint8_t)));
  s->prev = static_cast<std::uint16_t*>(zalloc(strm->opaque, s->w_size, sizeof(std::uint16_t)));
  s->head = static_cast<std::uint16_t*>(zalloc(strm->opaque, s->hash_size, sizeof(std::uint16_t)));

  s->lit_bufsize = 1u << (static_cast<unsigned int>(memLevel) + 6);  // 16K by default

  // overlay: pending_buf is lit_bufsize*4 bytes; d_buf and l_buf carve it up.
  auto* const overlay =
      static_cast<std::uint16_t*>(zalloc(strm->opaque, s->lit_bufsize, sizeof(std::uint16_t) + 2));
  s->pending_buf = reinterpret_cast<std::uint8_t*>(overlay);
  s->pending_buf_size = static_cast<std::uint32_t>(s->lit_bufsize) * 4u;

  if (s->window == nullptr || s->prev == nullptr || s->head == nullptr || overlay == nullptr)
  {
    s->status = kDeflateFinishState;
    strm->msg = const_cast<char*>("insufficient memory");
    deflateEnd(strm);
    return kZMemError;
  }
  // overlay carves pending_buf into d_buf (first half, as u16) and l_buf (top
  // third, as bytes): d_buf = overlay + lit_bufsize/2, l_buf = pending_buf +
  // 3*lit_bufsize (matches deflateInit2_.asm 0x0095C8F1..0x0095C8F9).
  s->d_buf = overlay + s->lit_bufsize / 2;
  s->l_buf = s->pending_buf + 3 * s->lit_bufsize;

  s->level = level;
  s->strategy = strategy;
  s->method = static_cast<std::uint8_t>(method);

  return deflateReset(strm);
}

/**
 * Address: 0x0095AD00 (FUN_0095AD00)
 * Mangled: deflate
 *
 * IDA signature:
 * int __cdecl deflate(z_streamp strm, int flush);
 *
 * The main compression driver: emit the zlib/gzip header on the first call,
 * flush any pending output, dispatch to the level's block compressor, handle the
 * flush modes (partial/sync/full via _tr_align / _tr_stored_block), and on
 * Z_FINISH emit the trailer (adler32 or gzip crc+size). Returns Z_OK,
 * Z_STREAM_END, Z_STREAM_ERROR or Z_BUF_ERROR.
 */
extern "C" int deflate(ZStream* strm, int flush)
{
  using namespace zlib;

  if (strm == nullptr)
  {
    return kZStreamError;
  }
  auto* const s = static_cast<DeflateState*>(strm->state);
  if (s == nullptr || flush > kDeflateFinish || flush < 0)
  {
    return kZStreamError;
  }
  if (strm->next_out == nullptr || (strm->next_in == nullptr && strm->avail_in != 0) ||
      (s->status == kDeflateFinishState && flush != kDeflateFinish))
  {
    strm->msg = const_cast<char*>("stream error");
    return kZStreamError;
  }
  if (strm->avail_out == 0)
  {
    strm->msg = const_cast<char*>("buffer error");
    return kZBufError;
  }

  const int old_flush = s->last_flush;
  s->strm = strm;
  s->last_flush = flush;

  // Write the zlib / gzip header.
  if (s->status == kDeflateInitState)
  {
    if (s->wrap == 2)
    {
      // gzip header.
      strm->adler = crc32(0, nullptr, 0);
      s->pending_buf[s->pending++] = 31;
      s->pending_buf[s->pending++] = 139;
      s->pending_buf[s->pending++] = 8;
      if (s->gzhead == nullptr)
      {
        s->pending_buf[s->pending++] = 0;
        s->pending_buf[s->pending++] = 0;
        s->pending_buf[s->pending++] = 0;
        s->pending_buf[s->pending++] = 0;
        s->pending_buf[s->pending++] = 0;
        s->pending_buf[s->pending++] =
            (s->level == 9) ? 2 : ((s->strategy >= kZHuffmanOnly || s->level < 2) ? 4 : 0);
        s->pending_buf[s->pending++] = 255;  // OS_CODE unknown
        s->status = kDeflateBusyState;
      }
      else
      {
        GzHeaderW* const h = s->gzhead;
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(
            (h->text ? 1 : 0) + (h->hcrc ? 2 : 0) + (h->extra == nullptr ? 0 : 4) +
            (h->name == nullptr ? 0 : 8) + (h->comment == nullptr ? 0 : 16));
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->time);
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->time >> 8);
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->time >> 16);
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->time >> 24);
        s->pending_buf[s->pending++] =
            (s->level == 9) ? 2 : ((s->strategy >= kZHuffmanOnly || s->level < 2) ? 4 : 0);
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->os);
        if (h->extra != nullptr)
        {
          s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->extra_len);
          s->pending_buf[s->pending++] = static_cast<std::uint8_t>(h->extra_len >> 8);
        }
        if (h->hcrc)
        {
          strm->adler = crc32(strm->adler, s->pending_buf, s->pending);
        }
        s->gzindex = 0;
        s->status = kDeflateExtraState;
      }
    }
    else
    {
      // zlib header.
      int level_flags;
      if (s->strategy >= kZHuffmanOnly || s->level < 2)
      {
        level_flags = 0;
      }
      else if (s->level < 6)
      {
        level_flags = 1;
      }
      else if (s->level == 6)
      {
        level_flags = 2;
      }
      else
      {
        level_flags = 3;
      }
      unsigned int header = ((kZDeflated + ((s->w_bits - 8) << 4)) << 8) |
                            (static_cast<unsigned int>(level_flags) << 6);
      if (s->strstart != 0)
      {
        header |= kPresetDict;
      }
      header += 31 - (header % 31);

      s->status = kDeflateBusyState;
      PutShortMSB(s, header);

      // Save the adler32 of the preset dictionary, if any.
      if (s->strstart != 0)
      {
        PutShortMSB(s, static_cast<unsigned int>(strm->adler >> 16));
        PutShortMSB(s, static_cast<unsigned int>(strm->adler & 0xffff));
      }
      strm->adler = adler32(0, nullptr, 0);
    }
  }

  // Write the gzip header fields (extra / name / comment / hcrc), if requested.
  if (s->status == kDeflateExtraState)
  {
    if (s->gzhead->extra != nullptr)
    {
      unsigned int beg = s->pending;
      while (s->gzindex < (s->gzhead->extra_len & 0xffff))
      {
        if (s->pending == s->pending_buf_size)
        {
          if (s->gzhead->hcrc && s->pending > beg)
          {
            strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
          }
          FlushPending(strm);
          beg = s->pending;
          if (s->pending == s->pending_buf_size)
          {
            break;
          }
        }
        s->pending_buf[s->pending++] = s->gzhead->extra[s->gzindex++];
      }
      if (s->gzhead->hcrc && s->pending > beg)
      {
        strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
      }
      if (s->gzindex == s->gzhead->extra_len)
      {
        s->gzindex = 0;
        s->status = kDeflateNameState;
      }
    }
    else
    {
      s->status = kDeflateNameState;
    }
  }
  if (s->status == kDeflateNameState)
  {
    if (s->gzhead->name != nullptr)
    {
      unsigned int beg = s->pending;
      int val;
      do
      {
        if (s->pending == s->pending_buf_size)
        {
          if (s->gzhead->hcrc && s->pending > beg)
          {
            strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
          }
          FlushPending(strm);
          beg = s->pending;
          if (s->pending == s->pending_buf_size)
          {
            val = 1;
            break;
          }
        }
        val = s->gzhead->name[s->gzindex++];
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(val);
      } while (val != 0);
      if (s->gzhead->hcrc && s->pending > beg)
      {
        strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
      }
      if (val == 0)
      {
        s->gzindex = 0;
        s->status = kDeflateCommentState;
      }
    }
    else
    {
      s->status = kDeflateCommentState;
    }
  }
  if (s->status == kDeflateCommentState)
  {
    if (s->gzhead->comment != nullptr)
    {
      unsigned int beg = s->pending;
      int val;
      do
      {
        if (s->pending == s->pending_buf_size)
        {
          if (s->gzhead->hcrc && s->pending > beg)
          {
            strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
          }
          FlushPending(strm);
          beg = s->pending;
          if (s->pending == s->pending_buf_size)
          {
            val = 1;
            break;
          }
        }
        val = s->gzhead->comment[s->gzindex++];
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(val);
      } while (val != 0);
      if (s->gzhead->hcrc && s->pending > beg)
      {
        strm->adler = crc32(strm->adler, s->pending_buf + beg, s->pending - beg);
      }
      if (val == 0)
      {
        s->status = kDeflateHcrcState;
      }
    }
    else
    {
      s->status = kDeflateHcrcState;
    }
  }
  if (s->status == kDeflateHcrcState)
  {
    if (s->gzhead->hcrc)
    {
      if (s->pending + 2 > s->pending_buf_size)
      {
        FlushPending(strm);
      }
      if (s->pending + 2 <= s->pending_buf_size)
      {
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler);
        s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler >> 8);
        strm->adler = crc32(0, nullptr, 0);
        s->status = kDeflateBusyState;
      }
    }
    else
    {
      s->status = kDeflateBusyState;
    }
  }

  // Flush as much pending output as possible.
  if (s->pending != 0)
  {
    FlushPending(strm);
    if (strm->avail_out == 0)
    {
      // Since avail_out is 0, deflate() will be called again with more output.
      s->last_flush = -1;
      return kZOk;
    }
  }
  else if (strm->avail_in == 0 && flush <= old_flush && flush != kDeflateFinish)
  {
    strm->msg = const_cast<char*>("buffer error");
    return kZBufError;
  }

  // User must not provide more input after the first FINISH.
  if (s->status == kDeflateFinishState && strm->avail_in != 0)
  {
    strm->msg = const_cast<char*>("buffer error");
    return kZBufError;
  }

  // Start a new block or continue the current one.
  if (strm->avail_in != 0 || s->lookahead != 0 ||
      (flush != kDeflateNoFlush && s->status != kDeflateFinishState))
  {
    const BlockState bstate = CompressByLevel(s, s->level, flush);

    if (bstate == kBlockFinishStarted || bstate == kBlockFinishDone)
    {
      s->status = kDeflateFinishState;
    }
    if (bstate == kBlockNeedMore || bstate == kBlockFinishStarted)
    {
      if (strm->avail_out == 0)
      {
        s->last_flush = -1;  // avoid BUF_ERROR next call, see above
      }
      return kZOk;
    }
    if (bstate == kBlockDone)
    {
      if (flush == kDeflatePartialFlush)
      {
        TreeAlign(s);
      }
      else
      {
        // FULL_FLUSH or SYNC_FLUSH: emit an empty stored block.
        TreeStoredBlock(s, nullptr, 0, 0);
        if (flush == kDeflateFullFlush)
        {
          // Forget the history so a full reset can restart from here.
          s->head[s->hash_size - 1] = 0;
          std::memset(s->head, 0, static_cast<std::size_t>(s->hash_size - 1) * sizeof(s->head[0]));
        }
      }
      FlushPending(strm);
      if (strm->avail_out == 0)
      {
        s->last_flush = -1;
        return kZOk;
      }
    }
  }

  if (flush != kDeflateFinish)
  {
    return kZOk;
  }
  if (s->wrap <= 0)
  {
    return kZStreamEnd;
  }

  // Write the trailer.
  if (s->wrap == 2)
  {
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler >> 8);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler >> 16);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->adler >> 24);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->total_in);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->total_in >> 8);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->total_in >> 16);
    s->pending_buf[s->pending++] = static_cast<std::uint8_t>(strm->total_in >> 24);
  }
  else
  {
    PutShortMSB(s, static_cast<unsigned int>(strm->adler >> 16));
    PutShortMSB(s, static_cast<unsigned int>(strm->adler & 0xffff));
  }
  FlushPending(strm);

  // If avail_out is zero, the trailer will be emitted on the next call.
  if (s->wrap > 0)
  {
    s->wrap = -s->wrap;  // write the trailer only once
  }
  return s->pending != 0 ? kZOk : kZStreamEnd;
}

/**
 * Address: 0x0095B4E0 (FUN_0095B4E0)
 * Mangled: deflateEnd
 *
 * IDA signature:
 * int __cdecl deflateEnd(z_streamp strm);
 *
 * Releases a deflate stream. Guards a null stream / state and a deflate_state
 * whose status is not one of the recognised init/gzip-header/busy/finish values
 * (Z_STREAM_ERROR). Otherwise it frees the four heap buffers the deflate_state
 * owns — pending_buf, head, prev and window — plus the state itself through the
 * stream's zfree callback, nulls strm->state, and returns Z_DATA_ERROR if the
 * stream was mid-operation (BUSY_STATE) or Z_OK otherwise. Verified 1:1 against
 * FUN_0095B4E0.asm (the free order is pending_buf -> head -> prev -> window ->
 * state; the IDA decompiler's state->w_mask etc. names are the real
 * window/prev/head at +0x38/+0x40/+0x44).
 */
extern "C" int deflateEnd(ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<DeflateState*>(strm->state);
  const int status = state->status;
  if (status != kDeflateInitState && status != kDeflateExtraState &&
      status != kDeflateNameState && status != kDeflateCommentState &&
      status != kDeflateHcrcState && status != kDeflateBusyState &&
      status != kDeflateFinishState)
  {
    return kZStreamError;
  }

  const auto zfree = reinterpret_cast<FreeFunc>(strm->zfree);
  if (state->pending_buf != nullptr)
  {
    zfree(strm->opaque, state->pending_buf);
  }
  if (state->head != nullptr)
  {
    zfree(strm->opaque, state->head);
  }
  if (state->prev != nullptr)
  {
    zfree(strm->opaque, state->prev);
  }
  if (state->window != nullptr)
  {
    zfree(strm->opaque, state->window);
  }
  zfree(strm->opaque, strm->state);
  strm->state = nullptr;

  return (status == kDeflateBusyState) ? kZDataError : kZOk;
}

// -----------------------------------------------------------------------------
// Extended tuning API: deflateSetHeader / deflatePrime / deflateTune /
// deflateBound. IDA never carved these into function boundaries (they sit in
// the untokenized 0x0095AB90-0x0095AC7A run between deflateSetDictionary's end
// (0x0095AB8E) and putShortMSB's start (0x0095AC80), each separated by int3
// padding); recovered here from a direct pefile+Capstone read of
// bin/2025.7.1/ForgedAlliance.exe, cross-checked line-for-line against the
// real zlib 1.2.3 deflate.c (madler/zlib tag v1.2.3, byte-identical to this
// project's vendored zlib.h).
//
// Caller search: an exhaustive scan of every section of
// bin/2025.7.1/ForgedAlliance.exe (relative CALL/JMP targets, and raw
// little-endian DWORD occurrences for address-taken/function-pointer-table
// use) found zero references to any of 0x0095AB90/0x0095ABC0/0x0095AC00
// anywhere in the image; the binary has no export table either, so these are
// not reachable via GetProcAddress. These three are genuine, byte-verified
// zlib public-API bodies that shipped in the binary but are never exercised
// by this build of the engine. deflateBound (0x0095AC40) is the same
// situation for its own address, but its body does reach an already-recovered
// helper (compressBoundRuntime) by real call, so recovering it gives that
// helper a live source-level caller.
// -----------------------------------------------------------------------------

/**
 * Address: 0x0095AB90 (FUN_0095AB90)
 * Mangled: deflateSetHeader
 *
 * IDA signature:
 * int __cdecl deflateSetHeader(z_streamp strm, gz_headerp head);
 *
 * Installs a caller-owned gzip header descriptor for the next deflate() call
 * to emit. The stream must already be in gzip mode (deflate_state::wrap == 2,
 * set by deflateInit2_ when windowBits > 15); returns Z_STREAM_ERROR for a
 * null stream/state or a non-gzip wrap, otherwise stores `head` into
 * deflate_state::gzhead and returns Z_OK. No source/binary side effect beyond
 * the single pointer store: deflate() itself reads gzhead later when it
 * writes the gzip header bytes.
 */
extern "C" int deflateSetHeader(ZStream* strm, GzHeaderW* head)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const s = static_cast<DeflateState*>(strm->state);
  if (s->wrap != 2)
  {
    return kZStreamError;
  }

  s->gzhead = head;
  return kZOk;
}

/**
 * Address: 0x0095ABC0 (FUN_0095ABC0)
 * Mangled: deflatePrime
 *
 * IDA signature:
 * int __cdecl deflatePrime(z_streamp strm, int bits, int value);
 *
 * Seeds the deflate bit accumulator with the low `bits` bits of `value` ahead
 * of the next deflate() call (used to inject out-of-band bits, e.g. a raw
 * deflate stream's leading bit alignment). Returns Z_STREAM_ERROR for a null
 * stream/state, otherwise sets deflate_state::bi_valid = bits and
 * deflate_state::bi_buf = (bits-masked) value, and returns Z_OK.
 */
extern "C" int deflatePrime(ZStream* strm, int bits, int value)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const s = static_cast<DeflateState*>(strm->state);
  s->bi_valid = bits;
  s->bi_buf = static_cast<std::uint16_t>(value & ((1 << bits) - 1));
  return kZOk;
}

/**
 * Address: 0x0095AC00 (FUN_0095AC00)
 * Mangled: deflateTune
 *
 * IDA signature:
 * int __cdecl deflateTune(z_streamp strm, int good_length, int max_lazy,
 *                          int nice_length, int max_chain);
 *
 * Overrides the four match-finder tuning parameters that LmInit derived from
 * the compression level (kConfigurationTable), for testing/experimentation.
 * Returns Z_STREAM_ERROR for a null stream/state, otherwise writes
 * good_match/max_lazy_match/nice_match/max_chain_length in that order and
 * returns Z_OK.
 */
extern "C" int deflateTune(ZStream* strm, int good_length, int max_lazy, int nice_length, int max_chain)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const s = static_cast<DeflateState*>(strm->state);
  s->good_match = static_cast<std::uint32_t>(good_length);
  s->max_lazy_match = static_cast<std::uint32_t>(max_lazy);
  s->nice_match = nice_length;
  s->max_chain_length = static_cast<std::uint32_t>(max_chain);
  return kZOk;
}

/**
 * Address: 0x0095AC40 (FUN_0095AC40)
 * Mangled: deflateBound
 *
 * IDA signature:
 * unsigned long __cdecl deflateBound(z_streamp strm, unsigned long sourceLen);
 *
 * Upper-bounds the compressed size of a `sourceLen`-byte input for output
 * buffer sizing. Computes zlib's conservative worst-case bound unconditionally
 * first (sourceLen plus its 1/8 and 1/64 shares plus 11 header/trailer bytes);
 * if the stream/state is unavailable, or the state is not running the
 * library's default window/hash geometry (w_bits != 15 or hash_bits != 15),
 * returns that conservative bound as-is. Otherwise defers to the tighter
 * compressBound() formula, which only holds for the default-parameters case.
 * Matches the binary exactly, including the call to compressBound at
 * 0x0095AC72 (recovered as compressBoundRuntime, 0x0095DF20).
 */
extern "C" unsigned long deflateBound(ZStream* strm, unsigned long sourceLen)
{
  using namespace zlib;

  // Conservative upper bound, computed unconditionally.
  const unsigned long destLen = sourceLen + ((sourceLen + 7) >> 3) + ((sourceLen + 63) >> 6) + 11u;

  // If can't get parameters, return the conservative bound.
  if (strm == nullptr || strm->state == nullptr)
  {
    return destLen;
  }

  // If not the default parameters, return the conservative bound.
  auto* const s = static_cast<DeflateState*>(strm->state);
  if (s->w_bits != 15 || s->hash_bits != 8 + 7)
  {
    return destLen;
  }

  // Default settings: return the tight bound for that case.
  return compressBoundRuntime(static_cast<unsigned int>(sourceLen));
}
