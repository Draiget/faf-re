#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <limits>
#include <type_traits>
#include <utility>

#include "moho/containers/BVIntSet.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Generic value-set container modeled directly on the binary 0x28-byte
   * payload used by the engine for category/entity set storage.
   *
   * Layout (1:1 with binary at every specialization):
   *   +0x00  U mUniverse;        // 4-byte typed universe handle
   *   +0x04  uint32 mReserved04; // gap (binary always-zero observed)
   *   +0x08  BVIntSet mBits;     // word-bitset payload (size 0x20)
   *
   * The `T` template parameter is a value-type marker only; it does not
   * appear in the layout. The `U` parameter must be a 4-byte trivially
   * copyable type that names the universe lane (e.g. EntityCategoryHelper,
   * EntIdUniverse, uint32_t).
   *
   * Convenience accessors below mirror the legacy EntityCategorySet API
   * so all category/word-range call sites operate on a single canonical type.
   */
  /**
   * Eight-byte aligned, which is what makes `mReserved04` a hole rather than a
   * field and puts this record on an eight-byte boundary inside everything
   * that embeds it. Read off `EntityCategoryLookupTable`
   * (RRuleGameRules.h), whose fallback set follows a 0x0C-byte
   * `msvc8::map` at **+0x10**: `FindOrFallback` (0x005552C0) returns
   * `lea eax,[esi+10h]` on its miss path. The same alignment is why that
   * map's nodes put their value at `node+0x10` rather than `node+0x0C` and
   * come out 0x60 bytes rather than 0x54 (`FUN_005569C0` / `FUN_005579D0`).
   *
   * The alignment is this record's, not `BVIntSet`'s: `SoundHandleIdPool`
   * (`{BVIntSet, std::uint32_t}`, CUserSoundManager.h) is 0x24, so the
   * embedded set alone does not round anything up to eight.
   */
  template <class T, class U>
  struct alignas(8) BVSet
  {
    // `EntIdUniverse` is empty (sizeof 1); `mReserved04` keeps `mBits` at
    // +0x08 either way.
    static_assert(sizeof(U) <= 4u, "BVSet<T,U>::U must fit the 4-byte universe lane.");

    /**
     * The value iterator (0x0C): a copy of the set's universe, then the
     * `BVIntSetIndex` walk over `mBits`. The universe turns an index back into
     * a `T`; for `EntIdUniverse` it is empty, so copying it emits nothing -
     * which is why `begin`/`end` (0x006E79D0 / 0x006E7A00) store only
     * +0x04/+0x08 and `Add`'s +0x00 store copies an undefined lane.
     */
    class const_iterator
    {
    public:
      const_iterator(const U& universe, const BVIntSetIndex& index) noexcept
        : mUniverse(universe)
        , mIndex(index)
      {}

      /**
       * Address: 0x00534960 (FUN_00534960 -- `U::FromIndex` through the
       *   universe lane: `mov ecx,[eax] / mov eax,[ecx] / push [eax+8] / call
       *   [eax+0x14]`, the category universe's vtable slot 5. Zero callers;
       *   every use inlined it.)
       */
      [[nodiscard]] T operator*() const { return mUniverse.FromIndex(mIndex.mValue); }

      /**
       * Address: 0x00534940 (FUN_00534940 -- `mValue = mOwnerSet->GetNext(mValue)`,
       *   returning the iterator. Zero callers.)
       * Address: 0x006E7A40 (FUN_006E7A40 -- the same body in the ent-id
       *   translation unit; not an ICF twin only because the `call`
       *   displacement differs. Zero callers.)
       */
      const_iterator& operator++()
      {
        mIndex.mValue = mIndex.mOwnerSet->GetNext(mIndex.mValue);
        return *this;
      }

      /**
       * Address: 0x00534970 (FUN_00534970 -- `cmp ecx,[edx+8] / setne al`,
       *   the value lanes only. Zero callers; ICF twin FUN_006E7A70 is `skip`.)
       */
      [[nodiscard]] bool operator!=(const const_iterator& rhs) const noexcept { return mIndex.mValue != rhs.mIndex.mValue; }
      [[nodiscard]] bool operator==(const const_iterator& rhs) const noexcept { return mIndex.mValue == rhs.mIndex.mValue; }

    private:
      U mUniverse;          // +0x00
      BVIntSetIndex mIndex; // +0x04
    };

    static gpg::RType* sType;

    U mUniverse{};               // +0x00
    std::uint32_t mReserved04{}; // +0x04 (binary-facing gap)
    BVIntSet mBits{};            // +0x08 (size 0x20)

    BVSet() noexcept = default;

    BVSet(const BVSet& other) : mUniverse(other.mUniverse), mReserved04(other.mReserved04), mBits(other.mBits) {}

    /**
     * Address: 0x0073B550 (FUN_0073B550 -- copy assignment for `BVSet<EntId, EntIdUniverse>` out of line: the empty universe emits nothing and +0x04 is not written, then `mBits = other.mBits` inline -- `mFirstWordIndex` (+0x08) and the word vector's `AssignFrom` 0x004028E0 (+0x10); no self-test; usercall this=ESI, source=EAX; emitted beside CSimDriver's ICommandSink members, zero callers, unreachable; formerly `CopyDwordAndFastVectorLane` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
     */
    BVSet& operator=(const BVSet& other)
    {
      if (this != &other) {
        mUniverse = other.mUniverse;
        mReserved04 = other.mReserved04;
        mBits = other.mBits;
      }
      return *this;
    }

    BVSet(BVSet&& other) noexcept
      : mUniverse(other.mUniverse), mReserved04(other.mReserved04), mBits(other.mBits)
    {
      other.mUniverse = U{};
      other.mReserved04 = 0u;
    }

    BVSet& operator=(BVSet&& other) noexcept
    {
      if (this != &other) {
        mUniverse = other.mUniverse;
        mReserved04 = other.mReserved04;
        mBits = other.mBits;
        other.mUniverse = U{};
        other.mReserved04 = 0u;
      }
      return *this;
    }

    ~BVSet() = default;

    /**
     * Address: 0x006E7A30 (FUN_006E7A30 -- `add ecx,8 / jmp BVIntSet::Count`,
     *   a `__thiscall` forwarder that counts the set embedded at `+0x08`.)
     * Address: 0x006D1940 (FUN_006D1940 -- the two-operand sibling:
     *   `mov edi,eax / add edi,8 / lea esi,[ebx+8] / call
     *   BVIntSet::RemoveAllFrom`, differencing one owner's embedded set against
     *   another's and handing back the source.)
     *
     * Both are zero-caller and unreachable, and both were transcribed as free
     * functions over a `BVIntSetEmbeddedOwnerRuntimeView` reach-in in
     * moho/containers/BVIntSet.cpp (RULE ONE), removed 2026-09-22.
     *
     * The `{4-byte lane, 4-byte gap, BVIntSet at +0x08}` shape they operate on
     * is this record's -- but it is also `moho::IdPool`'s
     * (`{mNextLowId, mReserved04, mReleasedLows}`, moho/sim/IdPool.h), and the
     * two cannot be told apart from these bodies alone: neither reads the lanes
     * ahead of the set. The addresses are recorded on both, and neither type
     * grows a member for them, because adding an uncalled `Count()` here would
     * relocate the orphan rather than retire it. `Bits().Count()` and
     * `Bits().RemoveAllFrom(...)` are what a caller writes.
     */
    [[nodiscard]] const BVIntSet& Bits() const noexcept { return mBits; }
    [[nodiscard]] BVIntSet& Bits() noexcept { return mBits; }

    /**
     * What `Add` returns: the set the value now sits in, its position there,
     * and whether it was newly inserted (0x10 bytes). The set pointer is
     * `&mBits`, stored twice: once for the set, once inside the position.
     */
    struct AddResult
    {
      BVIntSet* mSet;          // +0x00
      BVIntSetIndex mPosition; // +0x04
      bool mWasInserted;       // +0x0C
    };

    /**
     * Address: 0x006E5660 (FUN_006E5660, BVSet<EntId,EntIdUniverse>::Add -
     *   `this` in ecx, `BVIntSet::Add` (0x004036A0) on `this+8`, then the
     *   16-byte result written through the hidden return slot. Out-of-line
     *   only in `CDecoder::DecodeEntIdSet` (0x006E4F5F); its other adds are
     *   inlined straight to `BVIntSet::Add`. Formerly
     *   `AddEntityIdSetValueWithScratch` over a `BVIntSetAddScratch` in
     *   CDecoder.cpp.)
     *
     * What it does:
     * Inserts `value` into the set.
     */
    AddResult Add(const T value)
    {
      const BVIntSetAddResult added = mBits.Add(static_cast<unsigned int>(value));
      return AddResult{added.mOwnerSet, added, added.mWasInserted};
    }

    /**
     * Iterates every set value in `mBits` and invokes `fn(value)` for each.
     * Mirrors the legacy `BVSet::ForEachValue` API used across recovered
     * sim/UI code that walks selection/category sets.
     */
    template <class F>
    void ForEachValue(F&& fn) const
    {
      mBits.ForEachValue(std::forward<F>(fn));
    }

    // ---- legacy EntityCategorySet API surface (delegated to mBits) ----

    void ResetToEmpty(const U& universe) noexcept
    {
      mUniverse = universe;
      mReserved04 = 0u;
      mBits = BVIntSet{};
    }

    // Convenience overload for the common case where the universe is supplied
    // as a raw 4-byte word (e.g. `lookup.wordUniverseHandle`). Reinterprets
    // the bits as the typed `U` lane via the static-size guarantee above.
    template <class V = U, std::enable_if_t<!std::is_same_v<V, std::uint32_t>, int> = 0>
    void ResetToEmpty(const std::uint32_t universeBits) noexcept
    {
      static_assert(std::is_trivially_copyable_v<U>, "BVSet<T,U>::U must be trivially copyable.");
      std::memcpy(&mUniverse, &universeBits, sizeof(U));
      mReserved04 = 0u;
      mBits = BVIntSet{};
    }

    [[nodiscard]] std::size_t WordCount() const noexcept
    {
      const auto* const begin = mBits.mWords.start_;
      const auto* const end = mBits.mWords.end_;
      if (!begin || !end || end < begin) {
        return 0u;
      }
      return static_cast<std::size_t>(end - begin);
    }

    [[nodiscard]] bool Empty() const noexcept { return WordCount() == 0u; }

    [[nodiscard]] const std::uint32_t* WordData() const noexcept { return mBits.mWords.start_; }
    [[nodiscard]] std::uint32_t* WordData() noexcept { return mBits.mWords.start_; }
    [[nodiscard]] const std::uint32_t* WordEnd() const noexcept { return mBits.mWords.end_; }

    /**
     * Address: 0x006E79D0 (FUN_006E79D0, BVSet<EntId,EntIdUniverse>::begin --
     *   `{universe, {&mBits, mBits.GetNext(-1)}}`, BVIntSet::BeginIndex inlined;
     *   out-of-line for Sim::LuaSimCallback. Formerly
     *   `BuildEntIdSetBeginIteratorRuntime` in SimRecoveryRuntime.cpp.)
     */
    [[nodiscard]] const_iterator begin() const
    {
      return const_iterator(mUniverse, const_cast<BVIntSet&>(mBits).BeginIndex());
    }

    /**
     * Address: 0x006E7A00 (FUN_006E7A00, BVSet<EntId,EntIdUniverse>::end --
     *   `{universe, {&mBits, (mFirstWordIndex + wordCount) << 5}}`,
     *   BVIntSet::EndIndex inlined; re-evaluated on every pass of
     *   Sim::LuaSimCallback's loop. Formerly `BuildEntIdSetEndCursorLane` in
     *   Sim.cpp.)
     */
    [[nodiscard]] const_iterator end() const
    {
      return const_iterator(mUniverse, const_cast<BVIntSet&>(mBits).EndIndex());
    }

    /**
     * The storage word holding absolute word index `absoluteWordIndex`, or
     * `WordEnd()` when the set does not cover it.
     */
    [[nodiscard]] const std::uint32_t* FindWord(const std::uint32_t absoluteWordIndex) const noexcept
    {
      if (absoluteWordIndex < mBits.mFirstWordIndex) {
        return WordEnd();
      }

      const std::size_t localWordIndex =
        static_cast<std::size_t>(absoluteWordIndex - mBits.mFirstWordIndex);
      if (localWordIndex >= WordCount()) {
        return WordEnd();
      }

      return WordData() + localWordIndex;
    }

    [[nodiscard]] bool ContainsBit(const std::uint32_t categoryBitIndex) const noexcept
    {
      const std::uint32_t* const wordIt = FindWord(categoryBitIndex >> 5u);
      if (wordIt == WordEnd()) {
        return false;
      }
      return (((*wordIt) >> (categoryBitIndex & 0x1Fu)) & 1u) != 0u;
    }
  };

  template <class T, class U>
  gpg::RType* BVSet<T, U>::sType = nullptr;

  using BVSetWord32 = BVSet<std::uint32_t, std::uint32_t>;
  static_assert(offsetof(BVSetWord32, mUniverse) == 0x00, "BVSet::mUniverse offset must be 0x00");
  static_assert(offsetof(BVSetWord32, mReserved04) == 0x04, "BVSet::mReserved04 offset must be 0x04");
  static_assert(offsetof(BVSetWord32, mBits) == 0x08, "BVSet::mBits offset must be 0x08");
  static_assert(sizeof(BVSetWord32) == 0x28, "BVSet size must be 0x28");
  static_assert(alignof(BVSetWord32) == 8, "BVSet must be 8-aligned");
  static_assert(sizeof(BVSetWord32::const_iterator) == 0x0C, "BVSet::const_iterator size must be 0x0C");
} // namespace moho
