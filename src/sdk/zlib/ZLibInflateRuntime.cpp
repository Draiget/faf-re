// zlib inflate runtime recovery (ForgedAlliance.exe statically links zlib 1.2.x
// as zlib.lib). These recovered bodies match the binary at their given
// addresses and override the library copies via .obj-before-.lib resolution;
// the recovered TU is ExcludedFromBuild (a source-faithful record verified
// per-TU) so it never conflicts with the shipping zlib.lib.

#include "zlib/ZLibInflate.h"

#include <cstdlib>
#include <cstring>

// Already-recovered zlib leaves this TU calls by name. adler32/crc32 live in the
// sibling ZLibAdlerRuntime.cpp / ZLibCrcRuntime.cpp; inflateReset is defined
// below in this TU. All are extern "C" to match the linked zlib ABI.
extern "C" unsigned long adler32(unsigned long adler, const unsigned char* buf, unsigned int len);
extern "C" unsigned long crc32(unsigned long crc, const unsigned char* buf, unsigned int len);

namespace {

// zlib inftrees.c: build a set of Huffman decoding tables. Recovered from
// FUN_0095CEC0 (see the out-of-line definition below). File-static like the
// zlib original (`local`); inflate is the only caller.
int inflate_table(zlib::CodeType type, unsigned short* lens, unsigned int codes,
                  zlib::Code** table, unsigned int* bits, unsigned short* work);

// zlib inffast.c: decode as much as possible in the hot literal/length + match
// loop. Recovered from FUN_0095CA00. File-static; inflate is the only caller.
void inflate_fast(zlib::ZStream* strm, unsigned int start);

// zlib inflate.c: slide freshly produced output into the sliding window,
// allocating it on first use. Recovered from FUN_00958F80. File-static; called
// from inflate and inflateSetDictionary.
int updatewindow(zlib::ZStream* strm, unsigned int out);

} // namespace

/**
 * Address: 0x00958DC0 (FUN_00958DC0)
 * Mangled: inflateReset
 *
 * IDA signature:
 * int __cdecl inflateReset(z_streamp strm);
 *
 * Resets an inflate stream to the start of a new inflate operation without
 * reallocating: clears the running counts and message, sets adler to 1, and
 * reinitialises the inflate_state (mode = HEAD, dmax = 32768, cleared window /
 * bit-accumulator / dictionary flags) and points lencode/distcode/next at the
 * state's own codes[] table. Returns Z_STREAM_ERROR for a null stream or state,
 * otherwise Z_OK. Verified 1:1 against FUN_00958DC0.asm (this build predates the
 * HEAD magic-base cookie, so HEAD == 0, and state->check is intentionally not
 * reset here).
 */
extern "C" int inflateReset(zlib::ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<InflateState*>(strm->state);

  strm->total_in  = 0;
  strm->total_out = 0;
  state->total    = 0;
  strm->msg       = nullptr;
  strm->adler     = 1;  // to support ill-conceived Java test suite

  state->mode     = kInflateModeHead;
  state->last     = 0;
  state->havedict = 0;
  state->dmax     = 32768u;
  state->head     = nullptr;
  state->wsize    = 0;
  state->whave    = 0;
  state->wnext    = 0;
  state->hold     = 0;
  state->bits     = 0;
  state->lencode  = state->codes;
  state->distcode = state->codes;
  state->next     = state->codes;

  return kZOk;
}

/**
 * Address: 0x0095A670 (FUN_0095A670)
 * Mangled: inflateEnd
 *
 * IDA signature:
 * int __cdecl inflateEnd(z_streamp strm);
 *
 * Releases an inflate stream: frees the sliding window (if allocated) and the
 * inflate_state itself through the stream's zfree callback, then nulls
 * strm->state. Returns Z_STREAM_ERROR for a null stream, a null state, or a
 * missing zfree callback; otherwise Z_OK. Verified 1:1 against FUN_0095A670.asm
 * (all three guards precede any free; the freed pointer the IDA decompiler calls
 * `state->w_mask` is state->window at +0x34).
 */
extern "C" int inflateEnd(zlib::ZStream* strm)
{
  using namespace zlib;

  if (strm == nullptr || strm->state == nullptr || strm->zfree == nullptr)
  {
    return kZStreamError;
  }

  auto* const state = static_cast<InflateState*>(strm->state);
  const auto zfree = reinterpret_cast<FreeFunc>(strm->zfree);

  if (state->window != nullptr)
  {
    zfree(strm->opaque, state->window);
  }
  zfree(strm->opaque, strm->state);
  strm->state = nullptr;

  return kZOk;
}

/**
 * Address: 0x0095C9D0 (FUN_0095C9D0)
 * Mangled: zcalloc
 *
 * zlib's default allocator (zutil.c): ignores the opaque handle and returns
 * malloc(items * size). Matches FUN_0095C9D0.asm (imul items,size then malloc).
 */
extern "C" void* zcalloc([[maybe_unused]] void* opaque, unsigned int items, unsigned int size)
{
  return std::malloc(items * size);
}

/**
 * Address: 0x0095C9F0 (FUN_0095C9F0)
 * Mangled: zcfree
 *
 * zlib's default deallocator (zutil.c): ignores the opaque handle and frees the
 * address with the CRT free.
 */
extern "C" void zcfree([[maybe_unused]] void* opaque, void* address)
{
  std::free(address);
}

/**
 * Address: 0x00958E70 (FUN_00958E70)
 * Mangled: inflateInit2_
 *
 * IDA signature:
 * int __cdecl inflateInit2_(z_streamp strm, int windowBits, const char* version, int stream_size);
 *
 * Allocates and initialises an inflate stream. Rejects a version whose first
 * char isn't '1' or a stream_size other than sizeof(z_stream) (Z_VERSION_ERROR),
 * and a null stream (Z_STREAM_ERROR). Installs the default zcalloc/zcfree when
 * the caller left them null, allocates the inflate_state through zalloc
 * (Z_MEM_ERROR on failure), then derives wrap and the window size from
 * windowBits: for windowBits >= 0, wrap = (windowBits >> 4) + 1 and (when
 * < 48) windowBits &= 15; for windowBits < 0, wrap = 0 and windowBits negated.
 * A resulting window size outside 8..15 frees the state and returns
 * Z_STREAM_ERROR; otherwise it records wbits, clears the window pointer, and
 * tail-calls inflateReset. Verified 1:1 against FUN_00958E70.asm.
 */
extern "C" int inflateInit2_(zlib::ZStream* strm, int windowBits,
                             const char* version, int stream_size)
{
  using namespace zlib;

  if (version == nullptr || *version != '1' || stream_size != static_cast<int>(sizeof(ZStream)))
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

  auto* const state = static_cast<InflateState*>(
      reinterpret_cast<AllocFunc>(strm->zalloc)(strm->opaque, 1, sizeof(InflateState)));
  if (state == nullptr)
  {
    return kZMemError;
  }
  strm->state = state;

  if (windowBits >= 0)
  {
    state->wrap = (windowBits >> 4) + 1;
    if (windowBits < 48)
    {
      windowBits &= 15;
    }
  }
  else
  {
    state->wrap = 0;
    windowBits = -windowBits;
  }

  if (windowBits < 8 || windowBits > 15)
  {
    reinterpret_cast<FreeFunc>(strm->zfree)(strm->opaque, state);
    strm->state = nullptr;
    return kZStreamError;
  }

  state->wbits  = static_cast<std::uint32_t>(windowBits);
  state->window = nullptr;
  return inflateReset(strm);
}

/**
 * Address: 0x00958F40 (FUN_00958F40)
 * Mangled: inflateInit_
 *
 * IDA signature:
 * int __cdecl inflateInit_(z_streamp strm, const char* version, int stream_size);
 *
 * Thin wrapper: initialises an inflate stream with the default window size
 * (DEF_WBITS = 15) via inflateInit2_.
 */
extern "C" int inflateInit_(zlib::ZStream* strm, const char* version, int stream_size)
{
  return inflateInit2_(strm, zlib::kZDefaultWindowBits, version, stream_size);
}

namespace {

/**
 * Address: 0x00958F80 (FUN_00958F80)
 * Mangled: updatewindow (zlib inflate.c, static)
 *
 * IDA signature:
 * int __usercall updatewindow@<eax>(unsigned out@<eax>, z_streamp strm@<ebx>);
 *
 * Copies the `out` bytes most recently produced at strm->next_out into the
 * inflate sliding window, allocating the window (1 << wbits bytes) through the
 * stream's zalloc on first use. Maintains wsize/whave/wnext. Returns 1 if the
 * window allocation failed, otherwise 0. Verified 1:1 against FUN_00958F80.asm:
 * the compiler gave this local a custom eax/ebx register convention, but the
 * body is the ordinary zlib updatewindow — expressed here as a normal free
 * function since every call site is file-local.
 */
int updatewindow(zlib::ZStream* strm, unsigned int out)
{
  using namespace zlib;

  auto* const state = static_cast<InflateState*>(strm->state);

  // Allocate the window on first use (byte-sized: 1 << wbits).
  if (state->window == nullptr)
  {
    state->window = static_cast<std::uint8_t*>(
        reinterpret_cast<AllocFunc>(strm->zalloc)(strm->opaque, 1u << state->wbits, 1));
    if (state->window == nullptr)
    {
      return 1;
    }
  }

  // Initialise the window size on first use.
  if (state->wsize == 0)
  {
    state->wsize = 1u << state->wbits;
    state->wnext = 0;
    state->whave = 0;
  }

  // Copy state->wsize or fewer output bytes into the window.
  const unsigned int copied = out - strm->avail_out;  // bytes produced this call
  if (copied >= state->wsize)
  {
    std::memcpy(state->window, strm->next_out - state->wsize, state->wsize);
    state->wnext = 0;
    state->whave = state->wsize;
  }
  else
  {
    unsigned int dist = state->wsize - state->wnext;
    if (dist > copied)
    {
      dist = copied;
    }
    std::memcpy(state->window + state->wnext, strm->next_out - copied, dist);
    const unsigned int rest = copied - dist;
    if (rest != 0)
    {
      std::memcpy(state->window, strm->next_out - rest, rest);
      state->wnext = rest;
      state->whave = state->wsize;
    }
    else
    {
      state->wnext += dist;
      if (state->wnext == state->wsize)
      {
        state->wnext = 0;
      }
      if (state->whave < state->wsize)
      {
        state->whave += dist;
      }
    }
  }
  return 0;
}

/**
 * Address: 0x0095CEC0 (FUN_0095CEC0)
 * Mangled: inflate_table (zlib inftrees.c, static)
 *
 * IDA signature:
 * int __cdecl inflate_table(codetype type, unsigned short* lens, unsigned codes,
 *                           code** table, unsigned* bits, unsigned short* work);
 *
 * Builds a set of zlib Huffman decoding tables (root table + sub-tables) into
 * *table, advancing *table past the space used, and returns the root index bits
 * in *bits. Returns 0 on success, -1 for an over- or incomplete code set, and 1
 * when a LENS build would exceed the ENOUGH bound. Verified 1:1 against
 * FUN_0095CEC0.asm; the base/extra source tables and the ENOUGH == 1456 LENS
 * bound match the binary's .rodata and its two guarded checks.
 */
int inflate_table(zlib::CodeType type, unsigned short* lens, unsigned int codes,
                  zlib::Code** table, unsigned int* bits, unsigned short* work)
{
  using namespace zlib;

  unsigned int len;                 // a code's length in bits
  unsigned int sym;                 // index of code symbols
  unsigned int min, max;            // minimum and maximum code lengths
  unsigned int root;                // number of index bits for root table
  unsigned int curr;                // number of index bits for current table
  unsigned int drop;                // code bits to drop for sub-table
  int left;                         // number of prefix codes available
  unsigned int used;                // code entries in table used
  unsigned int huff;                // Huffman code
  unsigned int incr;                // for incrementing code, index
  unsigned int fill;                // index for replicating entries
  unsigned int low;                 // low bits for current root entry
  unsigned int mask;                // mask for low root bits
  Code here;                        // table entry for duplication
  Code* next;                       // next available space in table
  const std::uint16_t* base;        // base value table to use
  const std::uint16_t* extra;       // extra bits table to use
  int match;                        // use base and extra for symbol >= match
  unsigned short count[kMaxBits + 1];  // number of codes of each length
  unsigned short offs[kMaxBits + 1];   // offsets in table for each length

  // Accumulate lengths for codes (assumes lens[] all in 0..MAXBITS).
  for (len = 0; len <= kMaxBits; ++len)
  {
    count[len] = 0;
  }
  for (sym = 0; sym < codes; ++sym)
  {
    ++count[lens[sym]];
  }

  // Bound code lengths, force root to be within code lengths.
  root = *bits;
  for (max = kMaxBits; max >= 1; --max)
  {
    if (count[max] != 0)
    {
      break;
    }
  }
  if (root > max)
  {
    root = max;
  }
  if (max == 0)  // no symbols to code at all
  {
    here.op = 64;  // invalid code marker
    here.bits = 1;
    here.val = 0;
    *(*table)++ = here;  // make a table to force an error
    *(*table)++ = here;
    *bits = 1;
    return 0;  // no symbols, but wait for decoding to report error
  }
  for (min = 1; min < max; ++min)
  {
    if (count[min] != 0)
    {
      break;
    }
  }
  if (root < min)
  {
    root = min;
  }

  // Check for an over-subscribed or incomplete set of lengths.
  left = 1;
  for (len = 1; len <= kMaxBits; ++len)
  {
    left <<= 1;
    left -= count[len];
    if (left < 0)
    {
      return -1;  // over-subscribed
    }
  }
  if (left > 0 && (type == kCodeTypeCodes || max != 1))
  {
    return -1;  // incomplete set
  }

  // Generate offsets into symbol table for each length for sorting.
  offs[1] = 0;
  for (len = 1; len < kMaxBits; ++len)
  {
    offs[len + 1] = static_cast<unsigned short>(offs[len] + count[len]);
  }

  // Sort symbols by length, by symbol order within each length.
  for (sym = 0; sym < codes; ++sym)
  {
    if (lens[sym] != 0)
    {
      work[offs[lens[sym]]++] = static_cast<unsigned short>(sym);
    }
  }

  // Set up for code type. `match` is compared signed against work[sym]:
  // work[sym] <  match -> literal, work[sym] == match -> end-of-block,
  // work[sym] >  match -> length/distance (base/extra indexed by work[sym]).
  // These exact match values (CODES=19, LENS=256, DISTS=-1) are the binary's
  // (FUN_0095CEC0.asm var_6C loads at 0x0095D0EA/0x0095D0FC and default -1).
  switch (type)
  {
    case kCodeTypeCodes:
      base = extra = work;  // dummy value -- not used
      match = 19;           // code-length codes are all literals (sym < 19)
      break;
    case kCodeTypeLens:
      base = kLenBase - 257;
      extra = kLenExt - 257;
      match = 256;           // symbol 256 is end-of-block
      break;
    default:  // DISTS
      base = kDistBase;
      extra = kDistExt;
      match = -1;            // every distance symbol uses base/extra
      break;
  }

  // Initialize state for loop.
  huff = 0;             // starting code
  sym = 0;              // starting code symbol
  len = min;            // starting code length
  next = *table;        // current table to fill in
  curr = root;          // current table index bits
  drop = 0;             // current bits to drop from code for index
  low = static_cast<unsigned int>(-1);  // trigger new sub-table when len > root
  used = 1u << root;    // use root table entries
  mask = used - 1;      // mask for comparing low

  // Check available table space (LENS only, ENOUGH bound).
  if (type == kCodeTypeLens && used >= kEnoughCodes)
  {
    return 1;
  }

  // Process all codes and make table entries.
  for (;;)
  {
    // Create table entry. Classify work[sym] against `match` (signed 3-way).
    here.bits = static_cast<std::uint8_t>(len - drop);
    const int workSym = static_cast<int>(work[sym]);
    if (workSym < match)
    {
      here.op = 0;  // literal
      here.val = work[sym];
    }
    else if (workSym > match)
    {
      here.op = static_cast<std::uint8_t>(extra[work[sym]]);
      here.val = base[work[sym]];
    }
    else
    {
      here.op = 96;  // end of block
      here.val = 0;
    }

    // Replicate for those indices with low len bits equal to huff.
    incr = 1u << (len - drop);
    fill = 1u << curr;
    min = fill;  // save offset to next table
    do
    {
      fill -= incr;
      next[(huff >> drop) + fill] = here;
    } while (fill != 0);

    // Backwards increment the len-bit code huff.
    incr = 1u << (len - 1);
    while ((huff & incr) != 0)
    {
      incr >>= 1;
    }
    if (incr != 0)
    {
      huff &= incr - 1;
      huff += incr;
    }
    else
    {
      huff = 0;
    }

    // Go to next symbol, update count, len.
    ++sym;
    if (--count[len] == 0)
    {
      if (len == max)
      {
        break;
      }
      len = lens[work[sym]];
    }

    // Create new sub-table if needed.
    if (len > root && (huff & mask) != low)
    {
      // If first time, transition to sub-tables.
      if (drop == 0)
      {
        drop = root;
      }

      // Increment past last table.
      next += min;  // here min is 1 << curr

      // Determine length of next table.
      curr = len - drop;
      left = static_cast<int>(1u << curr);
      while (curr + drop < max)
      {
        left -= count[curr + drop];
        if (left <= 0)
        {
          break;
        }
        ++curr;
        left <<= 1;
      }

      // Check for enough space (LENS only).
      used += 1u << curr;
      if (type == kCodeTypeLens && used >= kEnoughCodes)
      {
        return 1;
      }

      // Point entry in root table to sub-table.
      low = huff & mask;
      (*table)[low].op = static_cast<std::uint8_t>(curr);
      (*table)[low].bits = static_cast<std::uint8_t>(root);
      (*table)[low].val = static_cast<std::uint16_t>(next - *table);
    }
  }

  // Fill in remaining table entry if code is incomplete (guaranteed to have at
  // most one remaining entry, since if the code is incomplete, the maximum code
  // length that was allowed to get this far is one bit).
  here.op = 64;  // invalid code marker
  here.bits = static_cast<std::uint8_t>(len - drop);
  here.val = 0;
  while (huff != 0)
  {
    // When done with sub-table, drop back to root table.
    if (drop != 0 && (huff & mask) != low)
    {
      drop = 0;
      len = root;
      next = *table;
      here.bits = static_cast<std::uint8_t>(len);
    }

    // Put invalid code marker in table.
    next[huff >> drop] = here;

    // Backwards increment the len-bit code huff.
    incr = 1u << (len - 1);
    while ((huff & incr) != 0)
    {
      incr >>= 1;
    }
    if (incr != 0)
    {
      huff &= incr - 1;
      huff += incr;
    }
    else
    {
      huff = 0;
    }
  }

  // Set return parameters.
  *table += used;
  *bits = root;
  return 0;
}

/**
 * Address: 0x0095CA00 (FUN_0095CA00)
 * Mangled: inflate_fast (zlib inffast.c, static)
 *
 * IDA signature:
 * void __usercall inflate_fast(z_streamp strm@<...>, unsigned start);
 *
 * The decode fast path: while at least six input bytes and 258 output bytes are
 * available (guaranteed by the caller), decode literal/length + distance codes
 * straight from the local bit buffer, emitting literals and copying matches from
 * the output or the sliding window, until an end-of-block, an error, or the
 * fast-path guard fails. Then it restores strm->next_in/next_out/avail_* and the
 * state's hold/bits. `start` is inflate's initial avail_out for this call, used
 * to bound the safe output region. Verified 1:1 against FUN_0095CA00.asm (window
 * pointers are byte-sized; this build carries no INFLATE_STRICT dmax check).
 */
void inflate_fast(zlib::ZStream* strm, unsigned int start)
{
  using namespace zlib;

  auto* const state = static_cast<InflateState*>(strm->state);

  // Copy state to local variables (PUP: pointers are pre-decremented by one, so
  // the read/write forms `*++ptr` / `*++out` match the binary's addressing).
  const std::uint8_t* in = strm->next_in - 1;
  const std::uint8_t* const last = in + (strm->avail_in - 5);
  std::uint8_t* out = strm->next_out - 1;
  std::uint8_t* const beg = out - (start - strm->avail_out);
  std::uint8_t* const end = out + (strm->avail_out - 257);

  const unsigned int wsize = state->wsize;
  const unsigned int whave = state->whave;
  const unsigned int wnext = state->wnext;
  std::uint8_t* const window = state->window;
  std::uint32_t hold = state->hold;
  unsigned int bits = state->bits;
  const Code* const lcode = state->lencode;
  const Code* const dcode = state->distcode;
  const unsigned int lmask = (1u << state->lenbits) - 1;
  const unsigned int dmask = (1u << state->distbits) - 1;

  Code here;             // retrieved table entry
  unsigned int op;       // code bits, operation, extra bits, or window position
  unsigned int len;      // match length, unused bytes
  unsigned int dist;     // match distance
  const std::uint8_t* from;  // where to copy match from

  // Decode literals and length/distances until end-of-block or not enough input
  // data or output space.
  do
  {
    if (bits < 15)
    {
      hold += static_cast<std::uint32_t>(in[1]) << bits;
      in += 2;
      hold += static_cast<std::uint32_t>(in[0]) << (bits + 8);
      bits += 16;
    }
    here = lcode[hold & lmask];
  dolen:
    op = here.bits;
    hold >>= op;
    bits -= op;
    op = here.op;
    if (op == 0)  // literal
    {
      *++out = static_cast<std::uint8_t>(here.val);
    }
    else if ((op & 0x10) != 0)  // length base
    {
      len = here.val;
      op &= 0x0F;  // number of extra bits
      if (op != 0)
      {
        if (bits < op)
        {
          hold += static_cast<std::uint32_t>(*++in) << bits;
          bits += 8;
        }
        len += hold & ((1u << op) - 1);
        hold >>= op;
        bits -= op;
      }
      if (bits < 15)
      {
        hold += static_cast<std::uint32_t>(in[1]) << bits;
        in += 2;
        hold += static_cast<std::uint32_t>(in[0]) << (bits + 8);
        bits += 16;
      }
      here = dcode[hold & dmask];
    dodist:
      op = here.bits;
      hold >>= op;
      bits -= op;
      op = here.op;
      if ((op & 0x10) != 0)  // distance base
      {
        dist = here.val;
        op &= 0x0F;  // number of extra bits
        if (bits < op)
        {
          hold += static_cast<std::uint32_t>(*++in) << bits;
          bits += 8;
          if (bits < op)
          {
            hold += static_cast<std::uint32_t>(*++in) << bits;
            bits += 8;
          }
        }
        dist += hold & ((1u << op) - 1);
        hold >>= op;
        bits -= op;
        op = static_cast<unsigned int>(out - beg);  // max distance in output
        if (dist > op)  // see if copy from window
        {
          op = dist - op;  // distance back in window
          if (op > whave)
          {
            strm->msg = const_cast<char*>("invalid distance too far back");
            state->mode = kModeBad;
            break;
          }
          from = window - 1;
          if (wnext == 0)  // very common case
          {
            from += wsize - op;
            if (op < len)  // some from window
            {
              len -= op;
              do
              {
                *++out = *++from;
              } while (--op != 0);
              from = out - dist;  // rest from output
            }
          }
          else if (wnext < op)  // wrap around window
          {
            from += wsize + wnext - op;
            op -= wnext;
            if (op < len)  // some from end of window
            {
              len -= op;
              do
              {
                *++out = *++from;
              } while (--op != 0);
              from = window - 1;
              if (wnext < len)  // some from start of window
              {
                op = wnext;
                len -= op;
                do
                {
                  *++out = *++from;
                } while (--op != 0);
                from = out - dist;  // rest from output
              }
            }
          }
          else  // contiguous in window
          {
            from += wnext - op;
            if (op < len)  // some from window
            {
              len -= op;
              do
              {
                *++out = *++from;
              } while (--op != 0);
              from = out - dist;  // rest from output
            }
          }
          while (len > 2)
          {
            *++out = *++from;
            *++out = *++from;
            *++out = *++from;
            len -= 3;
          }
          if (len != 0)
          {
            *++out = *++from;
            if (len > 1)
            {
              *++out = *++from;
            }
          }
        }
        else
        {
          from = out - dist;  // copy direct from output
          do  // minimum length is three
          {
            *++out = *++from;
            *++out = *++from;
            *++out = *++from;
            len -= 3;
          } while (len > 2);
          if (len != 0)
          {
            *++out = *++from;
            if (len > 1)
            {
              *++out = *++from;
            }
          }
        }
      }
      else if ((op & 0x40) == 0)  // 2nd level distance code
      {
        here = dcode[here.val + (hold & ((1u << op) - 1))];
        goto dodist;
      }
      else
      {
        strm->msg = const_cast<char*>("invalid distance code");
        state->mode = kModeBad;
        break;
      }
    }
    else if ((op & 0x40) == 0)  // 2nd level length code
    {
      here = lcode[here.val + (hold & ((1u << op) - 1))];
      goto dolen;
    }
    else if ((op & 0x20) != 0)  // end-of-block
    {
      state->mode = kModeType;
      break;
    }
    else
    {
      strm->msg = const_cast<char*>("invalid literal/length code");
      state->mode = kModeBad;
      break;
    }
  } while (in < last && out < end);

  // Return unused bytes (on entry, bits < 8, so in won't go too far back).
  len = bits >> 3;
  in -= len;
  bits -= len << 3;
  hold &= (1u << bits) - 1;

  // Update state and return. avail_in/avail_out are recomputed unconditionally
  // from the (possibly negative) pointer differences, exactly as the binary does
  // (last - in + 5, end - out + 257).
  strm->next_in = const_cast<std::uint8_t*>(in) + 1;
  strm->next_out = out + 1;
  strm->avail_in = static_cast<unsigned int>((last - in) + 5);
  strm->avail_out = static_cast<unsigned int>((end - out) + 257);
  state->hold = hold;
  state->bits = bits;
}

// zlib inflate.c permitted-header check helper (STORED-block dictionary id path
// uses the gzip magic 0x8b1f; the zlib header modulo-31 check is inline below).
constexpr unsigned int kGzipMagic = 0x8b1fu;  // gzip method+magic (0x1f, 0x8b)

} // namespace

/**
 * Address: 0x00959070 (FUN_00959070)
 * Mangled: inflate
 *
 * IDA signature:
 * int __cdecl inflate(z_streamp strm, int flush);
 *
 * The zlib inflate() state machine: consumes strm->next_in and produces
 * strm->next_out, advancing through the zlib/gzip header, dynamic/fixed/stored
 * blocks (delegating the hot path to inflate_fast and table construction to
 * inflate_table), and the trailing check/length words, saving the sliding
 * window through updatewindow on each return. Returns Z_OK / Z_STREAM_END /
 * Z_BUF_ERROR on progress, Z_NEED_DICT when a preset dictionary is required, or
 * a negative error code. Verified 1:1 against FUN_00959070.asm: the mode enum,
 * every state displacement, the 29-arm dispatch, the gzip-header field stores,
 * and the inf_leave window/check bookkeeping all match the binary.
 */
extern "C" int inflate(zlib::ZStream* strm, int flush)
{
  using namespace zlib;

  // Validate stream.
  if (strm == nullptr || strm->state == nullptr || strm->next_out == nullptr ||
      (strm->next_in == nullptr && strm->avail_in != 0))
  {
    return kZStreamError;
  }

  auto* const state = static_cast<InflateState*>(strm->state);
  if (state->mode == kModeType)
  {
    state->mode = kModeTypedo;  // skip check
  }

  // Load registers with state in inflate() for speed.
  std::uint8_t* put = strm->next_out;
  unsigned int left = strm->avail_out;
  const std::uint8_t* next = strm->next_in;
  unsigned int have = strm->avail_in;
  std::uint32_t hold = state->hold;
  unsigned int bits = state->bits;

  const unsigned int in = have;    // starting available input for this call
  unsigned int out = left;         // available output at last flush (CHECK resets)
  int ret = kZOk;

  Code here;             // current decoding table entry
  unsigned int copy;     // number of stored or match bytes to copy
  const std::uint8_t* from;  // where to copy match bytes from
  Code last;             // parent table entry
  unsigned int len;      // length to copy for repeats, bits to drop

  for (;;)
  {
    switch (state->mode)
    {
      case kModeHead:
        if (state->wrap == 0)
        {
          state->mode = kModeTypedo;
          break;
        }
        while (bits < 16)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if ((state->wrap & 2) != 0 && hold == kGzipMagic)  // gzip header
        {
          state->check = crc32(0, nullptr, 0);
          {
            std::uint8_t hbuf[2] = {static_cast<std::uint8_t>(hold),
                                    static_cast<std::uint8_t>(hold >> 8)};
            state->check = crc32(state->check, hbuf, 2);
          }
          hold = 0;
          bits = 0;
          state->mode = kModeFlags;
          break;
        }
        state->flags = 0;  // expect zlib header
        if (state->head != nullptr)
        {
          state->head->done = -1;
        }
        if ((state->wrap & 1) == 0 ||  // check if zlib header allowed
            ((((hold & 0xFF) << 8) + (hold >> 8)) % 31) != 0)
        {
          strm->msg = const_cast<char*>("incorrect header check");
          state->mode = kModeBad;
          break;
        }
        if ((hold & 0x0F) != 8)  // Z_DEFLATED
        {
          strm->msg = const_cast<char*>("unknown compression method");
          state->mode = kModeBad;
          break;
        }
        hold >>= 4;
        bits -= 4;
        len = (hold & 0x0F) + 8;
        if (len > state->wbits)
        {
          strm->msg = const_cast<char*>("invalid window size");
          state->mode = kModeBad;
          break;
        }
        state->dmax = 1u << len;
        strm->adler = state->check = adler32(0, nullptr, 0);
        state->mode = (hold & 0x200) != 0 ? kModeDictid : kModeType;
        hold = 0;
        bits = 0;
        break;

      case kModeFlags:
        while (bits < 16)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        state->flags = static_cast<std::int32_t>(hold);
        if ((state->flags & 0xFF) != 8)  // Z_DEFLATED
        {
          strm->msg = const_cast<char*>("unknown compression method");
          state->mode = kModeBad;
          break;
        }
        if ((state->flags & 0xE000) != 0)
        {
          strm->msg = const_cast<char*>("unknown header flags set");
          state->mode = kModeBad;
          break;
        }
        if (state->head != nullptr)
        {
          state->head->text = static_cast<std::int32_t>((hold >> 8) & 1);
        }
        if ((state->flags & 0x0200) != 0)
        {
          std::uint8_t hbuf[2] = {static_cast<std::uint8_t>(hold),
                                  static_cast<std::uint8_t>(hold >> 8)};
          state->check = crc32(state->check, hbuf, 2);
        }
        hold = 0;
        bits = 0;
        state->mode = kModeTime;
        [[fallthrough]];
      case kModeTime:
        while (bits < 32)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if (state->head != nullptr)
        {
          state->head->time = hold;
        }
        if ((state->flags & 0x0200) != 0)
        {
          std::uint8_t hbuf[4] = {static_cast<std::uint8_t>(hold),
                                  static_cast<std::uint8_t>(hold >> 8),
                                  static_cast<std::uint8_t>(hold >> 16),
                                  static_cast<std::uint8_t>(hold >> 24)};
          state->check = crc32(state->check, hbuf, 4);
        }
        hold = 0;
        bits = 0;
        state->mode = kModeOs;
        [[fallthrough]];
      case kModeOs:
        while (bits < 16)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if (state->head != nullptr)
        {
          state->head->xflags = static_cast<std::int32_t>(hold & 0xFF);
          state->head->os = static_cast<std::int32_t>(hold >> 8);
        }
        if ((state->flags & 0x0200) != 0)
        {
          std::uint8_t hbuf[2] = {static_cast<std::uint8_t>(hold),
                                  static_cast<std::uint8_t>(hold >> 8)};
          state->check = crc32(state->check, hbuf, 2);
        }
        hold = 0;
        bits = 0;
        state->mode = kModeExlen;
        [[fallthrough]];
      case kModeExlen:
        if ((state->flags & 0x0400) != 0)
        {
          while (bits < 16)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          state->length = hold & 0xFFFF;
          if (state->head != nullptr)
          {
            state->head->extra_len = hold & 0xFFFF;
          }
          if ((state->flags & 0x0200) != 0)
          {
            std::uint8_t hbuf[2] = {static_cast<std::uint8_t>(hold),
                                    static_cast<std::uint8_t>(hold >> 8)};
            state->check = crc32(state->check, hbuf, 2);
          }
          hold = 0;
          bits = 0;
        }
        else if (state->head != nullptr)
        {
          state->head->extra = nullptr;
        }
        state->mode = kModeExtra;
        [[fallthrough]];
      case kModeExtra:
        if ((state->flags & 0x0400) != 0)
        {
          copy = state->length;
          if (copy > have)  { copy = have; }
          if (copy != 0)
          {
            if (state->head != nullptr && state->head->extra != nullptr)
            {
              len = state->head->extra_len - state->length;
              if (len + copy > state->head->extra_max)
              {
                copy = state->head->extra_max - len;
              }
              std::memcpy(state->head->extra + len, next, copy);
            }
            if ((state->flags & 0x0200) != 0)
            {
              state->check = crc32(state->check, next, copy);
            }
            have -= copy;
            next += copy;
            state->length -= copy;
          }
          if (state->length != 0)  { goto inf_leave; }
        }
        state->length = 0;
        state->mode = kModeName;
        [[fallthrough]];
      case kModeName:
        if ((state->flags & 0x0800) != 0)
        {
          if (have == 0)  { goto inf_leave; }
          copy = 0;
          do
          {
            len = next[copy++];
            if (state->head != nullptr && state->head->name != nullptr &&
                state->length < state->head->name_max)
            {
              state->head->name[state->length++] = static_cast<std::uint8_t>(len);
            }
          } while (len != 0 && copy < have);
          if ((state->flags & 0x0200) != 0)
          {
            state->check = crc32(state->check, next, copy);
          }
          have -= copy;
          next += copy;
          if (len != 0)  { goto inf_leave; }
        }
        else if (state->head != nullptr)
        {
          state->head->name = nullptr;
        }
        state->length = 0;
        state->mode = kModeComment;
        [[fallthrough]];
      case kModeComment:
        if ((state->flags & 0x1000) != 0)
        {
          if (have == 0)  { goto inf_leave; }
          copy = 0;
          do
          {
            len = next[copy++];
            if (state->head != nullptr && state->head->comment != nullptr &&
                state->length < state->head->comm_max)
            {
              state->head->comment[state->length++] = static_cast<std::uint8_t>(len);
            }
          } while (len != 0 && copy < have);
          if ((state->flags & 0x0200) != 0)
          {
            state->check = crc32(state->check, next, copy);
          }
          have -= copy;
          next += copy;
          if (len != 0)  { goto inf_leave; }
        }
        else if (state->head != nullptr)
        {
          state->head->comment = nullptr;
        }
        state->mode = kModeHcrc;
        [[fallthrough]];
      case kModeHcrc:
        if ((state->flags & 0x0200) != 0)
        {
          while (bits < 16)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          if (hold != (state->check & 0xFFFF))
          {
            strm->msg = const_cast<char*>("header crc mismatch");
            state->mode = kModeBad;
            break;
          }
          hold = 0;
          bits = 0;
        }
        if (state->head != nullptr)
        {
          state->head->hcrc = static_cast<std::int32_t>((state->flags >> 9) & 1);
          state->head->done = 1;
        }
        strm->adler = state->check = crc32(0, nullptr, 0);
        state->mode = kModeType;
        break;

      case kModeDictid:
        while (bits < 32)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        strm->adler = state->check =
            ((hold >> 24) & 0xFF) | ((hold >> 8) & 0xFF00) |
            ((hold << 8) & 0xFF0000) | ((hold << 24) & 0xFF000000);
        hold = 0;
        bits = 0;
        state->mode = kModeDict;
        [[fallthrough]];
      case kModeDict:
        if (state->havedict == 0)
        {
          strm->next_out = put;
          strm->avail_out = left;
          strm->next_in = const_cast<std::uint8_t*>(next);
          strm->avail_in = have;
          state->hold = hold;
          state->bits = bits;
          return kZNeedDict;
        }
        strm->adler = state->check = adler32(0, nullptr, 0);
        state->mode = kModeType;
        [[fallthrough]];
      case kModeType:
        if (flush == kZBlock)  { goto inf_leave; }
        [[fallthrough]];
      case kModeTypedo:
        if (state->last != 0)
        {
          hold >>= bits & 7;
          bits -= bits & 7;
          state->mode = kModeCheck;
          break;
        }
        while (bits < 3)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        state->last = static_cast<std::int32_t>(hold & 1);
        hold >>= 1;
        --bits;
        switch (hold & 3)
        {
          case 0:  // stored block
            state->mode = kModeStored;
            break;
          case 1:  // fixed block
            state->lencode = kLenFix;   // fixedtables(): point at the
            state->lenbits = 9;         // precomputed fixed Huffman tables
            state->distcode = kDistFix; // (inffixed.h), matching the binary's
            state->distbits = 5;        // 0x0095988F/0x0095989D stores
            state->mode = kModeLen;     // decode codes
            break;
          case 2:  // dynamic block
            state->mode = kModeTable;
            break;
          default:  // case 3
            strm->msg = const_cast<char*>("invalid block type");
            state->mode = kModeBad;
            break;
        }
        hold >>= 2;
        bits -= 2;
        break;

      case kModeStored:
        hold >>= bits & 7;
        bits -= bits & 7;  // go to byte boundary
        while (bits < 32)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if ((hold & 0xFFFF) != ((hold >> 16) ^ 0xFFFF))
        {
          strm->msg = const_cast<char*>("invalid stored block lengths");
          state->mode = kModeBad;
          break;
        }
        state->length = hold & 0xFFFF;
        hold = 0;
        bits = 0;
        state->mode = kModeCopy;
        [[fallthrough]];
      case kModeCopy:
        copy = state->length;
        if (copy != 0)
        {
          if (copy > have)  { copy = have; }
          if (copy > left)  { copy = left; }
          if (copy == 0)  { goto inf_leave; }
          std::memcpy(put, next, copy);
          have -= copy;
          next += copy;
          left -= copy;
          put += copy;
          state->length -= copy;
          break;
        }
        state->mode = kModeType;
        break;

      case kModeTable:
        while (bits < 14)
        {
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        state->nlen = (hold & 0x1F) + 257;
        hold >>= 5;
        state->ndist = (hold & 0x1F) + 1;
        hold >>= 5;
        state->ncode = (hold & 0x0F) + 4;
        hold >>= 4;
        bits -= 14;
        if (state->nlen > 286 || state->ndist > 30)
        {
          strm->msg = const_cast<char*>("too many length or distance symbols");
          state->mode = kModeBad;
          break;
        }
        state->have = 0;
        state->mode = kModeLenlens;
        [[fallthrough]];
      case kModeLenlens:
        while (state->have < state->ncode)
        {
          while (bits < 3)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          state->lens[kCodeLengthOrder[state->have++]] =
              static_cast<std::uint16_t>(hold & 7);
          hold >>= 3;
          bits -= 3;
        }
        while (state->have < 19)
        {
          state->lens[kCodeLengthOrder[state->have++]] = 0;
        }
        state->next = state->codes;
        state->lencode = state->next;
        state->lenbits = 7;
        ret = inflate_table(kCodeTypeCodes, state->lens, 19, &state->next,
                            &state->lenbits, state->work);
        if (ret != 0)
        {
          strm->msg = const_cast<char*>("invalid code lengths set");
          state->mode = kModeBad;
          break;
        }
        state->have = 0;
        state->mode = kModeCodelens;
        [[fallthrough]];
      case kModeCodelens:
        while (state->have < state->nlen + state->ndist)
        {
          for (;;)
          {
            here = state->lencode[hold & ((1u << state->lenbits) - 1)];
            if (here.bits <= bits)  { break; }
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          if (here.val < 16)
          {
            hold >>= here.bits;
            bits -= here.bits;
            state->lens[state->have++] = here.val;
          }
          else
          {
            if (here.val == 16)
            {
              len = here.bits + 2;
              while (bits < len)
              {
                if (have == 0)  { goto inf_leave; }
                --have;
                hold += static_cast<std::uint32_t>(*next++) << bits;
                bits += 8;
              }
              hold >>= here.bits;
              bits -= here.bits;
              if (state->have == 0)
              {
                strm->msg = const_cast<char*>("invalid bit length repeat");
                state->mode = kModeBad;
                break;
              }
              len = state->lens[state->have - 1];
              copy = 3 + (hold & 3);
              hold >>= 2;
              bits -= 2;
            }
            else if (here.val == 17)
            {
              len = here.bits + 3;
              while (bits < len)
              {
                if (have == 0)  { goto inf_leave; }
                --have;
                hold += static_cast<std::uint32_t>(*next++) << bits;
                bits += 8;
              }
              hold >>= here.bits;
              bits -= here.bits;
              len = 0;
              copy = 3 + (hold & 7);
              hold >>= 3;
              bits -= 3;
            }
            else
            {
              len = here.bits + 7;
              while (bits < len)
              {
                if (have == 0)  { goto inf_leave; }
                --have;
                hold += static_cast<std::uint32_t>(*next++) << bits;
                bits += 8;
              }
              hold >>= here.bits;
              bits -= here.bits;
              len = 0;
              copy = 11 + (hold & 0x7F);
              hold >>= 7;
              bits -= 7;
            }
            if (state->have + copy > state->nlen + state->ndist)
            {
              strm->msg = const_cast<char*>("invalid bit length repeat");
              state->mode = kModeBad;
              break;
            }
            while (copy-- != 0)
            {
              state->lens[state->have++] = static_cast<std::uint16_t>(len);
            }
          }
        }

        // Handle error breaks in while.
        if (state->mode == kModeBad)  { break; }

        // Build code tables.
        state->next = state->codes;
        state->lencode = state->next;
        state->lenbits = 9;
        ret = inflate_table(kCodeTypeLens, state->lens, state->nlen, &state->next,
                            &state->lenbits, state->work);
        if (ret != 0)
        {
          strm->msg = const_cast<char*>("invalid literal/lengths set");
          state->mode = kModeBad;
          break;
        }
        state->distcode = state->next;
        state->distbits = 6;
        ret = inflate_table(kCodeTypeDists, state->lens + state->nlen, state->ndist,
                            &state->next, &state->distbits, state->work);
        if (ret != 0)
        {
          strm->msg = const_cast<char*>("invalid distances set");
          state->mode = kModeBad;
          break;
        }
        state->mode = kModeLen;
        [[fallthrough]];
      case kModeLen:
        if (have >= 6 && left >= 258)
        {
          strm->next_out = put;
          strm->avail_out = left;
          strm->next_in = const_cast<std::uint8_t*>(next);
          strm->avail_in = have;
          state->hold = hold;
          state->bits = bits;
          inflate_fast(strm, out);
          put = strm->next_out;
          left = strm->avail_out;
          next = strm->next_in;
          have = strm->avail_in;
          hold = state->hold;
          bits = state->bits;
          break;
        }
        for (;;)
        {
          here = state->lencode[hold & ((1u << state->lenbits) - 1)];
          if (here.bits <= bits)  { break; }
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if (here.op != 0 && (here.op & 0xF0) == 0)
        {
          last = here;
          for (;;)
          {
            here = state->lencode[last.val +
                                  ((hold & ((1u << (last.bits + last.op)) - 1)) >> last.bits)];
            if (static_cast<unsigned int>(last.bits) + here.bits <= bits)  { break; }
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          hold >>= last.bits;
          bits -= last.bits;
        }
        hold >>= here.bits;
        bits -= here.bits;
        state->length = here.val;
        if (here.op == 0)  // literal
        {
          state->mode = kModeLit;
          break;
        }
        if ((here.op & 0x20) != 0)  // end of block
        {
          state->mode = kModeType;
          break;
        }
        if ((here.op & 0x40) != 0)  // invalid code
        {
          strm->msg = const_cast<char*>("invalid literal/length code");
          state->mode = kModeBad;
          break;
        }
        state->extra = static_cast<unsigned int>(here.op) & 0x0F;
        state->mode = kModeLenext;
        [[fallthrough]];
      case kModeLenext:
        if (state->extra != 0)
        {
          while (bits < state->extra)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          state->length += hold & ((1u << state->extra) - 1);
          hold >>= state->extra;
          bits -= state->extra;
        }
        state->mode = kModeDist;
        [[fallthrough]];
      case kModeDist:
        for (;;)
        {
          here = state->distcode[hold & ((1u << state->distbits) - 1)];
          if (here.bits <= bits)  { break; }
          if (have == 0)  { goto inf_leave; }
          --have;
          hold += static_cast<std::uint32_t>(*next++) << bits;
          bits += 8;
        }
        if ((here.op & 0xF0) == 0)
        {
          last = here;
          for (;;)
          {
            here = state->distcode[last.val +
                                   ((hold & ((1u << (last.bits + last.op)) - 1)) >> last.bits)];
            if (static_cast<unsigned int>(last.bits) + here.bits <= bits)  { break; }
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          hold >>= last.bits;
          bits -= last.bits;
        }
        hold >>= here.bits;
        bits -= here.bits;
        if ((here.op & 0x40) != 0)
        {
          strm->msg = const_cast<char*>("invalid distance code");
          state->mode = kModeBad;
          break;
        }
        state->offset = here.val;
        state->extra = static_cast<unsigned int>(here.op) & 0x0F;
        state->mode = kModeDistext;
        [[fallthrough]];
      case kModeDistext:
        if (state->extra != 0)
        {
          while (bits < state->extra)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          state->offset += hold & ((1u << state->extra) - 1);
          hold >>= state->extra;
          bits -= state->extra;
        }
        if (state->offset > state->whave + (out - left))
        {
          strm->msg = const_cast<char*>("invalid distance too far back");
          state->mode = kModeBad;
          break;
        }
        state->mode = kModeMatch;
        [[fallthrough]];
      case kModeMatch:
        if (left == 0)  { goto inf_leave; }
        copy = out - left;
        if (state->offset > copy)  // copy from window
        {
          copy = state->offset - copy;
          if (copy > state->wnext)
          {
            copy -= state->wnext;
            from = state->window + (state->wsize - copy);
          }
          else
          {
            from = state->window + (state->wnext - copy);
          }
          if (copy > state->length)  { copy = state->length; }
        }
        else  // copy from output
        {
          from = put - state->offset;
          copy = state->length;
        }
        if (copy > left)  { copy = left; }
        left -= copy;
        state->length -= copy;
        do
        {
          *put++ = *from++;
        } while (--copy != 0);
        if (state->length == 0)  { state->mode = kModeLen; }
        break;

      case kModeLit:
        if (left == 0)  { goto inf_leave; }
        *put++ = static_cast<std::uint8_t>(state->length);
        --left;
        state->mode = kModeLen;
        break;

      case kModeCheck:
        if (state->wrap != 0)
        {
          while (bits < 32)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          out -= left;
          strm->total_out += out;
          state->total += out;
          if (out != 0)
          {
            strm->adler = state->check =
                (state->flags != 0 ? crc32(state->check, put - out, out)
                                   : adler32(state->check, put - out, out));
          }
          out = left;
          if ((state->flags != 0 ? hold
                                 : (((hold >> 24) & 0xFF) | ((hold >> 8) & 0xFF00) |
                                    ((hold << 8) & 0xFF0000) | ((hold << 24) & 0xFF000000))) !=
              state->check)
          {
            strm->msg = const_cast<char*>("incorrect data check");
            state->mode = kModeBad;
            break;
          }
          hold = 0;
          bits = 0;
        }
        state->mode = kModeLength;
        [[fallthrough]];
      case kModeLength:
        if (state->wrap != 0 && state->flags != 0)
        {
          while (bits < 32)
          {
            if (have == 0)  { goto inf_leave; }
            --have;
            hold += static_cast<std::uint32_t>(*next++) << bits;
            bits += 8;
          }
          if (hold != (state->total & 0xFFFFFFFFu))
          {
            strm->msg = const_cast<char*>("incorrect length check");
            state->mode = kModeBad;
            break;
          }
          hold = 0;
          bits = 0;
        }
        state->mode = kModeDone;
        [[fallthrough]];
      case kModeDone:
        ret = kZStreamEnd;
        goto inf_leave;

      case kModeBad:
        ret = kZDataError;
        goto inf_leave;

      case kModeMem:
        return kZMemError;

      case kModeSync:
      default:
        return kZStreamError;
    }
  }

  // Return from inflate(), updating the total counts and the check value. If
  // there was no progress during the inflate() call, return a buffer error.
  // Call updatewindow() to create and/or update the window state. Note: a memory
  // error from inflate() is non-recoverable.
inf_leave:
  strm->next_out = put;
  strm->avail_out = left;
  strm->next_in = const_cast<std::uint8_t*>(next);
  strm->avail_in = have;
  state->hold = hold;
  state->bits = bits;
  // Save the window if it exists, or if any output was produced before mode
  // reached CHECK. This matches the binary's guard at 0x0095A4EF exactly
  // (wsize != 0 || (mode < CHECK && out != avail_out)); the newer zlib
  // `flush != Z_FINISH` sub-clause is absent in this pre-1.2.4 build.
  if (state->wsize != 0 ||
      (state->mode < kModeCheck && out != strm->avail_out))
  {
    if (updatewindow(strm, out) != 0)
    {
      state->mode = kModeMem;
      return kZMemError;
    }
  }
  len = in - strm->avail_in;
  const unsigned int outUsed = out - strm->avail_out;
  strm->total_in += len;
  strm->total_out += outUsed;
  state->total += outUsed;
  if (state->wrap != 0 && outUsed != 0)
  {
    strm->adler = state->check =
        (state->flags != 0 ? crc32(state->check, strm->next_out - outUsed, outUsed)
                           : adler32(state->check, strm->next_out - outUsed, outUsed));
  }
  strm->data_type = static_cast<std::int32_t>(state->bits) +
                    (state->last != 0 ? 64 : 0) +
                    (state->mode == kModeType ? 128 : 0);
  if ((len == 0 && outUsed == 0) || flush == kZFinish)
  {
    if (ret == kZOk)
    {
      ret = kZBufError;
    }
  }
  return ret;
}
