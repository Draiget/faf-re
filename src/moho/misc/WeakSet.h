#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <utility>

#include "legacy/containers/Set.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  /**
   * `Moho::WeakSet<T>`: a set of objects held by weak reference, which forgets
   * an object once it dies.
   *
   * It is an `msvc8::set` of `Entry {T*, WeakPtr<T>}` ordered by the object's
   * address. The tree header is the 12-byte `{proxy, _Myhead, _Mysize}` and a
   * node is 0x1C: links at +0x00/+0x04/+0x08, the address at +0x0C, the
   * `WeakPtr` at +0x10, colour and nil at +0x18/+0x19. The engine
   * instantiates it for `UserEntity` (the session's selection, extra-select,
   * orphan and visibility sets, the drag and bracket sets) and for `UserUnit`
   * (`UserArmy`'s idle registries, `CFormation`'s participants). The two
   * instantiations emit separate but byte-identical bodies:
   *
   * | | `WeakSet<UserEntity>` | `WeakSet<UserUnit>` |
   * |---|---|---|
   * | `Add` | 0x007AE1B0 | 0x00822270 |
   * | `begin` | 0x0066A060 | 0x007B25F0 |
   * | `++` | 0x007AE7E0 | 0x007F0490 |
   * | `Empty` | 0x0066A090 | 0x007B2620 |
   * | `SkipDead` | 0x0066A330 | 0x007B29C0 |
   * | `Size` | 0x007B59B0 | 0x00838AE0 (prune inlined) |
   * | set `insert` | 0x007AEDC0 | 0x00822420 |
   * | set `erase(it)` | 0x0066A550 | 0x007B30D0 |
   * | tree `++` | 0x0066ADD0 | 0x007B4D90 |
   *
   * An entry whose object has died keeps its node, with the `WeakPtr` null,
   * until a walk steps onto it: `begin()` and `++` erase every dead entry they
   * pass (`SkipDead`), so a walk only ever sees live objects, and `Size()` walks
   * rather than reading the tree's count. Only `Find` leaves dead entries where
   * they are.
   *
   * `Add`, `Find` and `Remove` all build a whole `Entry` for the key, the
   * `WeakPtr` included, because the key type *is* the entry: 0x007FDD50 and
   * 0x008676E0 link a stack `WeakPtr` onto the object's chain around a lookup
   * that only reads the address.
   */
  template <class T>
  class WeakSet
  {
  public:
    /** One element: the object's address, which orders the set, and a weak reference to it. */
    struct Entry
    {
      /**
       * Implicit on purpose: VC8's `set(first, last)` range constructor
       * converts each `T*` its source iterator yields through this, which is the
       * stack `Entry` 0x00822C50 builds per element.
       */
      Entry(T* const object) noexcept
        : mObject(object)
        , mRef(object)
      {}

      [[nodiscard]] bool operator<(const Entry& other) const noexcept
      {
        return mObject < other.mObject;
      }

      T* mObject;      // +0x00 (node +0x0C)
      WeakPtr<T> mRef; // +0x04 (node +0x10)
    };

    using set_type = msvc8::set<Entry>;
    using tree_iterator = typename set_type::iterator;
    using size_type = std::size_t;

    /**
     * The `{set, node}` cursor every walk keeps on the stack. `*` is the object,
     * `++` is the tree successor followed by `SkipDead` on the owning set.
     */
    class iterator
    {
    public:
      using iterator_category = std::forward_iterator_tag;
      using value_type = T*;
      using difference_type = std::ptrdiff_t;
      using pointer = T* const*;
      using reference = T*;

      iterator() = default;

      iterator(const WeakSet* const set, const tree_iterator it) noexcept
        : mSet(set)
        , mIt(it)
      {}

      /**
       * Address: 0x0066A300 (FUN_0066A300 -- `*it` for `WeakSet<UserEntity>` out
       *   of line: the node's `WeakPtr` decoded (`slot ? slot - 8 : 0`); callers
       *   `SCommandModeData::HandleEvent` 0x0081FCD0, the idle selector's set
       *   comparison 0x00868690 and `CWldSession::DoBeat` 0x00894530.)
       */
      [[nodiscard]] T* operator*() const noexcept
      {
        return mIt->mRef.GetObjectPtr();
      }

      /**
       * Address: 0x007AE7E0 (FUN_007AE7E0, Moho::WeakSet_UserEntity::Iterator::Next)
       * Address: 0x007F0490 (FUN_007F0490 -- the `WeakSet<UserUnit>` emission,
       *   `__stdcall` on the cursor; `CUIWorldView::HandleEvent` 0x008706D8,
       *   0x0087108C)
       * Address: 0x008484E0 (FUN_008484E0 -- another `WeakSet<UserEntity>`
       *   emission; no caller.)
       *
       * What it does:
       * The tree successor (0x0066ADD0 / 0x007B4D90), then `SkipDead` on the
       * cursor's own set.
       */
      iterator& operator++()
      {
        ++mIt;
        mIt = mSet->SkipDead(mIt);
        return *this;
      }

      iterator operator++(int)
      {
        iterator previous = *this;
        ++*this;
        return previous;
      }

      [[nodiscard]] bool operator==(const iterator& other) const noexcept
      {
        return mIt == other.mIt;
      }

      [[nodiscard]] tree_iterator base() const noexcept
      {
        return mIt;
      }

    private:
      const WeakSet* mSet = nullptr; // +0x00
      tree_iterator mIt{};           // +0x04
    };

    /**
     * Address: 0x007B25C0 (FUN_007B25C0 -- the `WeakSet<UserUnit>` constructor
     *   out of line: head bought through 0x007B4640, isNil=1, self-linked,
     *   count zero; callers `RangeRenderer` 0x007EF280,
     *   `SCommandModeData::HandleEvent` 0x0081FCD0 and `CUIWorldView`
     *   0x008704B6.)
     */
    WeakSet() = default;

    /**
     * Address: 0x00822210 (FUN_00822210 -- the `WeakSet<UserEntity>` copy
     *   constructor: `other.begin()` (0x0066A330 from the leftmost node), then
     *   the set's range constructor 0x00822C50 over `[begin, end)`. Reached per
     *   element from `msvc8::vector<WeakSet<UserEntity>>`'s `uninit_fill_n`
     *   0x00868DB0, and inlined into `CWldSession::GetExtraSelectList`
     *   0x00896730.)
     *
     * What it does:
     * Copies the live objects only: building `other.begin()` erases `other`'s
     * leading dead entries, and each `++` the rest.
     */
    WeakSet(const WeakSet& other)
      : mSet(other.begin(), other.end())
    {}

    /**
     * Address: 0x00865720 (FUN_00865720 -- `WeakSet<UserEntity>::operator=`:
     *   `if (this != &other) { erase(begin, end) 0x007AF740; _Copy 0x00867B20 }`;
     *   caller `CWldSession::ReleaseDrag` 0x00865920.)
     * Address: 0x00865750 (FUN_00865750 -- the same body again; no caller.)
     * Address: 0x00867800 (FUN_00867800 -- the same body again; no caller.)
     *
     * Member-wise, as VC8 generated it: the tree is copied dead entries and all.
     */
    WeakSet& operator=(const WeakSet& other) = default;

    /**
     * Address: 0x007B2530 (FUN_007B2530 -- `~WeakSet<UserEntity>`, the set's
     *   `_Tidy`: `erase(begin, end)` (0x007B33B0), free the head, zero head and
     *   count; 24 callers, the scope exits of local sets.)
     * Address: 0x007B2650 (FUN_007B2650 -- the same body emitted again; caller
     *   the range constructor's unwind.)
     * Address: 0x00868E50 (FUN_00868E50 -- the same body as
     *   `msvc8::vector<WeakSet<UserEntity>>`'s per-element destructor.)
     * Address: 0x007ABDE0 (FUN_007ABDE0 -- the same `_Tidy`; callers the
     *   camera Lua targets 0x007ABAE0/0x007ABEC0/0x007AC240,
     *   `SCommandModeData::HandleEvent` 0x0081FCD0, `cfunc_IssueDockCommandL`
     *   0x00840A70 and 0x00841C10.)
     * Address: 0x007ABE10 (FUN_007ABE10 -- the same; caller
     *   `CWldSession::DoBeat` 0x00894530.)
     * Address: 0x007AE270 (FUN_007AE270 -- the same; callers the range
     *   constructor's unwind 0x00822C50 and `DoBeat` 0x00894530. IDA names it
     *   `Broadcaster<SCameraTracking>::RemoveListener`.)
     */
    ~WeakSet() = default;

    /**
     * Address: 0x007AE1B0 (FUN_007AE1B0, Moho::WeakSet_UserEntity::Add)
     * Address: 0x00822270 (FUN_00822270 -- the `WeakSet<UserUnit>` emission:
     *   the stack `Entry` at [esp+14h] is linked onto the unit's chain
     *   (0x008222A9), `insert` 0x00822420 runs, the entry unlinks itself
     *   (0x008222DF, and through the funclet 0x00B94260 on a throw), and
     *   `{set, node, inserted}` goes back through the hidden result.)
     *
     * What it does:
     * Inserts `object` unless it is already there; returns the entry's cursor
     * and whether it was new.
     */
    std::pair<iterator, bool> Add(T* const object)
    {
      const Entry entry(object);
      const std::pair<tree_iterator, bool> result = mSet.insert(entry);
      return {iterator(this, result.first), result.second};
    }

    /**
     * Address: 0x008B4D00 (FUN_008B4D00 -- `GetEntitiesUnderCursor`'s
     *   select-edit merge step for `WeakSet<UserUnit>` (0x008B43F0): a stack
     *   `Entry` and the hinted `insert` 0x008B4F50 per unit. That merge calls
     *   this range `Add` here, which builds the same set without the hint.)
     *
     * What it does:
     * Adds every object in `[first, last)` through the set's range insert
     * (0x00868AF0, 0x00868A00; see `msvc8::set::insert(first, last)`).
     */
    template <class InputIt>
    void Add(const InputIt first, const InputIt last)
    {
      mSet.insert(first, last);
    }

    /**
     * What it does:
     * Erases the entry under `it` and returns the next live one: the set's
     * `erase(it)` (0x0066A550 / 0x007B30D0), then `SkipDead`. Inlined at each
     * use, as in the dragger's selectability prune (0x00863EB3..0x00863EC1).
     */
    iterator Erase(const iterator it)
    {
      return iterator(this, SkipDead(mSet.erase(it.base())));
    }

    /**
     * Address: 0x007FDD50 (FUN_007FDD50, Moho::WeakSet_UserEntity::Find)
     * Address: 0x00867780 (FUN_00867780 -- the same body again for
     *   `WeakSet<UserEntity>`; callers `SetSelection` 0x00896140,
     *   `RemoveFromVizUpdate` 0x00894230 and `SelectionDragger::DragRelease`
     *   0x00863870.)
     * Address: 0x0082CEA0 (FUN_0082CEA0 -- the `WeakSet<UserUnit>` emission:
     *   the stack `Entry`, `find` 0x0082E560, `{set, node}`; callers
     *   `AddCommandQueueToCommandGraph` 0x00826140, 0x008281E0, 0x0082BA20,
     *   the command-graph participant gate 0x008B4300 and
     *   `cfunc_UserUnitHasUnloadCommandQueuedUpL` 0x008C2810.)
     *
     * What it does:
     * The entry for `object` through the set's `find` (0x007FDFE0), or `end()`.
     * A dead entry is returned as it is.
     */
    [[nodiscard]] iterator Find(T* const object) const
    {
      const Entry entry(object);
      return iterator(this, mSet.find(entry));
    }

    /**
     * Address: 0x008676E0 (FUN_008676E0 -- `WeakSet<UserEntity>::Remove`: the
     *   stack `Entry`, then the set's `erase(key)` 0x00867AC0 (equal range,
     *   count, erase), whose count is the result.)
     * Address: 0x008B2890 (FUN_008B2890 -- the same body emitted again.)
     *
     * What it does:
     * Erases the entry for `object`; returns how many went (0 or 1).
     */
    size_type Remove(T* const object)
    {
      const Entry entry(object);
      return mSet.erase(entry);
    }

    /** Drops every entry: the set's `erase(begin(), end())` whole-tree path (0x007AF740). */
    void Clear()
    {
      mSet.clear();
    }

    /**
     * Address: 0x0066A060 (FUN_0066A060, Moho::WeakSet_UserEntity::First)
     * Address: 0x007B25F0 (FUN_007B25F0 -- the `WeakSet<UserUnit>` emission;
     *   `CUIWorldView::HandleEvent` 0x0087069F, 0x00871065.)
     *
     * What it does:
     * The first live entry, erasing the dead ones before it.
     */
    [[nodiscard]] iterator begin() const
    {
      return iterator(this, SkipDead(mSet.begin()));
    }

    [[nodiscard]] iterator end() const noexcept
    {
      return iterator(this, mSet.end());
    }

    /**
     * Address: 0x0066A090 (FUN_0066A090 -- `WeakSet<UserEntity>::Empty`)
     * Address: 0x007B2620 (FUN_007B2620 -- the `WeakSet<UserUnit>` emission.)
     *
     * What it does:
     * True when no live entry is left; the dead ones in front are erased on the
     * way.
     */
    [[nodiscard]] bool Empty() const
    {
      return SkipDead(mSet.begin()) == mSet.end();
    }

    /**
     * Address: 0x007B59B0 (FUN_007B59B0, Moho::WeakSet_UserEntity::size)
     * Address: 0x00838AE0 (FUN_00838AE0 -- the `WeakSet<UserUnit>` emission,
     *   with `SkipDead` inlined into the loop; callers `CFormation::
     *   ChooseFormation` 0x008384C0, `ISSUE_IncreaseCommandCount` 0x008B0C80 and
     *   the user Lua `GetIdleEngineers` 0x008BCEF0, `GetIdleFactories`
     *   0x008BD180 and `GetValidAttackingUnits` 0x008BD410.)
     *
     * What it does:
     * Counts the live entries by walking them, which erases every dead one; the
     * tree's own count still includes the dead.
     */
    [[nodiscard]] size_type Size() const
    {
      size_type count = 0;
      for (iterator it = begin(); it != end(); ++it) {
        ++count;
      }
      return count;
    }

  private:
    /**
     * Address: 0x0066A330 (FUN_0066A330, Moho::WeakSet_UserEntity::find)
     * Address: 0x007B29C0 (FUN_007B29C0 -- the `WeakSet<UserUnit>` emission.)
     *
     * What it does:
     * From `it`, erases entries whose object has died (`erase(it)`, 0x0066A550 /
     * 0x007B30D0) until a live one or the end; returns where it stopped. The
     * death test is `slot != 0 && slot - 8 != 0`, the decode of the `WeakPtr`.
     */
    tree_iterator SkipDead(tree_iterator it) const
    {
      while (it != mSet.end() && it->mRef.GetObjectPtr() == nullptr) {
        it = mSet.erase(it);
      }
      return it;
    }

    // Pruning dead entries is the only write a const walk makes; it is
    // invisible through the interface, so the tree is `mutable`.
    mutable set_type mSet; // +0x00
  };
} // namespace moho
