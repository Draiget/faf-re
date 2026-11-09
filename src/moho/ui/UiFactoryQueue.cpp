#include "moho/ui/UiPrivate.h"


/**
 * What it does:
 * Language-level default construction of one empty queue row. The binary never
 * emitted a standalone default constructor (every construction site uses the
 * `(blueprintId, count)` form at 0x00835D50 or the copy form at 0x00837670);
 * this exists only so the legacy vector template can name one.
 */
moho::FactoryQueueDisplayItem::FactoryQueueDisplayItem() noexcept
  : blueprintId()
  , count(0)
  , commands()
{}

/**
 * Address: 0x00835D50 (FUN_00835D50, sub_835D50)
 *
 * IDA signature:
 * struct_BuildQueueItem *__usercall sub_835D50@<eax>(struct_BuildQueueItem *result,
 *                                                    std::string *str1, int count);
 *
 * What it does:
 * Seeds the blueprint-id string to empty SSO state (`myRes=0x0F` at +0x18,
 * `mySize=0` at +0x14, `buf[0]=0` at +0x04) and assigns the source id into it,
 * stores the queued count at +0x1C, then zeroes the command-id vector's data
 * triple at +0x24/+0x28/+0x2C.
 */
moho::FactoryQueueDisplayItem::FactoryQueueDisplayItem(
  const fa::string& sourceBlueprintId,
  const std::int32_t sourceCount
)
  : blueprintId(sourceBlueprintId)
  , count(sourceCount)
  , commands()
{}

/**
 * Address: 0x00837670 (FUN_00837670, sub_837670)
 *
 * IDA signature:
 * struct_BuildQueueItem *__usercall sub_837670@<eax>(struct_BuildQueueItem *dest,
 *                                                    struct_BuildQueueItem *src@<edi>);
 *
 * What it does:
 * Copy-constructs one queue row in place: legacy-string assign of the blueprint
 * id, raw copy of the count lane at +0x1C, then legacy-vector copy assignment of
 * the command-id lane at +0x20 (`sub_6E2E60`).
 */
moho::FactoryQueueDisplayItem::FactoryQueueDisplayItem(
  const FactoryQueueDisplayItem& other
)
  : blueprintId(other.blueprintId)
  , count(other.count)
  , commands(other.commands)
{}

/**
 * Address: 0x00837AB0 (inside FUN_00837AA0, func_CpyBuildQueueItems)
 *
 * What it does:
 * Element assignment the copy loop inlines: `blueprintId.assign(src, 0, npos)`
 * at 0x00837AB7, `count = src.count` at 0x00837AC2, then legacy-vector copy
 * assignment of the command-id lane at 0x00837AC9. The binary carries no
 * self-assignment guard here.
 */
moho::FactoryQueueDisplayItem& moho::FactoryQueueDisplayItem::operator=(
  const FactoryQueueDisplayItem& other
)
{
  blueprintId.assign(other.blueprintId, 0u, fa::string::npos);
  count = other.count;
  commands = other.commands;
  return *this;
}
namespace
{

  constexpr const char* kFactoryQueueChangedModule = "/lua/ui/game/gamemain.lua";
  constexpr const char* kFactoryQueueChangedCallback = "OnQueueChanged";
  // The binary's diagnostic literal (0x00E43810, pushed at 0x0083633F) names
  // construction.lua even though the module it actually imports at 0x00836267 is
  // gamemain.lua. Preserved verbatim rather than regenerated from the import path.
  constexpr const char* kFactoryQueueChangedWarning =
    "Error running '/lua/ui/game/construction.lua:OnQueueChanged': %s";

  // Legacy vector growth guard for the 0x30-stride queue element: 0x008370D0
  // compares the requested capacity against 0x5555555 before allocating.
  constexpr std::uint32_t kFactoryQueueMaxCapacity = 0x5555555u;

  /**
   * Address: 0x00837AA0 (FUN_00837AA0, func_CpyBuildQueueItems)
   *
   * IDA signature:
   * struct_BuildQueueItem *__usercall func_CpyBuildQueueItems@<eax>(
   *     struct_BuildQueueItem *dest@<eax>, struct_BuildQueueItem *src@<ecx>,
   *     struct_BuildQueueItem *end@<ebx>);
   *
   * What it does:
   * Assigns one half-open range of queue rows onto an already-constructed
   * destination range and returns the advanced destination cursor.
   */
  FactoryQueueItem* CopyBuildQueueItems(
    FactoryQueueItem* const destination,
    FactoryQueueItem* const source,
    FactoryQueueItem* const end
  )
  {
    auto* sourceCursor = source;
    auto* destinationCursor = destination;
    while (sourceCursor != end) {
      *destinationCursor = *sourceCursor;
      ++sourceCursor;
      ++destinationCursor;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x008378B0 (FUN_008378B0, sub_8378B0)
   *
   * What it does:
   * Register-shuffling bridge the compiler emitted for the `std::copy` call in
   * the grow-in-place assignment branch: forwards `(destinationBegin,
   * sourceBegin, sourceEnd)` to `CopyBuildQueueItems`, with `sourceEnd` arriving
   * in `ebx` rather than on the stack.
   */
  FactoryQueueItem* CopyBuildQueueItemsThiscallAdapter(
    FactoryQueueItem* const sourceEnd,
    FactoryQueueItem* const sourceBegin,
    FactoryQueueItem* const destinationBegin
  )
  {
    return CopyBuildQueueItems(destinationBegin, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00837B00 (FUN_00837B00, func_DeleteRangeBuildQueueItems)
   *
   * IDA signature:
   * void __usercall func_DeleteRangeBuildQueueItems(struct_BuildQueueItem *begin@<eax>,
   *                                                 struct_BuildQueueItem *end);
   *
   * What it does:
   * Destroys one half-open range of queue rows in place: frees each row's
   * command-id buffer (`[item+0x24]`) and clears its triple, then frees the
   * blueprint-id string buffer when heap-backed and restores empty SSO state.
   */
  void DeleteRangeBuildQueueItems(
    FactoryQueueItem* begin,
    FactoryQueueItem* const end
  )
  {
    while (begin != end) {
      // Free the row's command-id buffer and null all three lanes: _Tidy().
      // The element is trivially destructible, so there is no per-element pass.
      begin->commands = decltype(begin->commands){};

      if (begin->blueprintId.myRes >= 0x10u) {
        ::operator delete(begin->blueprintId.bx.ptr);
      }
      begin->blueprintId.myRes = 0x0Fu;
      begin->blueprintId.mySize = 0u;
      begin->blueprintId.bx.buf[0] = '\0';

      ++begin;
    }
  }

  /**
   * Address: 0x00837120 (FUN_00837120, sub_837120)
   *
   * What it does:
   * Register-shuffling bridge for the destroy call in the reallocating
   * assignment branch: the range end arrives in `ecx` and the range begin on the
   * stack, and both are forwarded to `DeleteRangeBuildQueueItems`.
   */
  void DeleteRangeBuildQueueItemsThiscallAdapter(
    FactoryQueueItem* const rangeEnd,
    FactoryQueueItem* const rangeBegin
  )
  {
    DeleteRangeBuildQueueItems(rangeBegin, rangeEnd);
  }

  /**
   * Address: 0x00837DC0 (FUN_00837DC0, sub_837DC0)
   *
   * IDA signature:
   * struct_BuildQueueItem *__usercall sub_837DC0@<eax>(struct_BuildQueueItem *last,
   *                                                    struct_BuildQueueItem *dest,
   *                                                    struct_BuildQueueItem *first@<ecx>);
   *
   * What it does:
   * Copy-constructs `[first, last)` into raw storage at `destination` (rows are
   * built one at a time by 0x00837670) and returns the advanced destination
   * cursor. On a throw partway through, the rows already built are destroyed
   * (0x00837E17 walks `[destinationBegin, destinationCursor)` through 0x00837D20)
   * and the exception is rethrown.
   */
  FactoryQueueItem* UninitializedCopyBuildQueueItems(
    const FactoryQueueItem* const first,
    const FactoryQueueItem* const last,
    FactoryQueueItem* const destination
  )
  {
    FactoryQueueItem* destinationCursor = destination;
    try {
      for (const FactoryQueueItem* cursor = first; cursor != last; ++cursor) {
        if (destinationCursor != nullptr) {
          ::new (static_cast<void*>(destinationCursor)) FactoryQueueItem(*cursor);
        }
        ++destinationCursor;
      }
    } catch (...) {
      for (FactoryQueueItem* rollback = destination; rollback != destinationCursor; ++rollback) {
        rollback->~FactoryQueueItem();
      }
      throw;
    }
    return destinationCursor;
  }

  /**
   * Address: 0x008378E0 (FUN_008378E0, sub_8378E0)
   *
   * What it does:
   * Register-shuffling bridge for the `std::uninitialized_copy` calls in the
   * assignment branches: `[first, last)` arrive on the stack and the destination
   * arrives in the inherited `edx`, and all three are forwarded to
   * `UninitializedCopyBuildQueueItems`.
   */
  FactoryQueueItem* UninitializedCopyBuildQueueItemsAdapter(
    const FactoryQueueItem* const first,
    const FactoryQueueItem* const last,
    FactoryQueueItem* const destination
  )
  {
    return UninitializedCopyBuildQueueItems(first, last, destination);
  }

  /**
   * Address: 0x008370D0 (FUN_008370D0, sub_8370D0)
   *
   * IDA signature:
   * char __usercall sub_8370D0@<al>(gpg::fastvector_BuildQueueItem *lanes@<edi>,
   *                                 unsigned int capacity@<esi>);
   *
   * What it does:
   * Installs a fresh, empty 0x30-stride buffer of `capacity` rows into the queue
   * lane: rejects lengths past the legacy growth ceiling, allocates through the
   * checked 48-byte lane allocator (or `operator new(0)` for the empty case),
   * and republishes `_Myfirst`/`_Mylast`/`_Myend`.
   */
  bool AllocateBuildQueueStorage(
    FactoryQueueLanes& lanes,
    const std::uint32_t capacity
  )
  {
    if (capacity > kFactoryQueueMaxCapacity) {
      // 0x008370D8 tail-calls the lane's `_Xlen` emission (0x00837540), which is
      // the legacy MSVC8 vector length diagnostic.
      throw std::length_error("vector<T> too long");
    }

    // VC8 _Buy(n): drop to empty, then one exact-size allocation with
    // mLast == mFirst -- reserve() on an empty vector is precisely that.
    lanes = FactoryQueueLanes{};
    lanes.reserve(capacity);
    return true;
  }

  struct FactoryQueueItemMismatch
  {
    const FactoryQueueItem* left;  // +0x00
    const FactoryQueueItem* right; // +0x04
  };

  /**
   * Address: 0x00837FA0 (FUN_00837FA0, sub_837FA0)
   *
   * IDA signature:
   * _DWORD *__cdecl sub_837FA0(_DWORD *outPair, struct_BuildQueueItem *first1,
   *                            struct_BuildQueueItem *last1,
   *                            struct_BuildQueueItem *first2, int, int);
   *
   * What it does:
   * `std::mismatch` over two queue ranges. Two rows match when their blueprint
   * ids compare equal (0x00837FDB) and their counts at +0x1C are identical
   * (0x00837FE7); the command-id lane is deliberately not part of the test.
   */
  [[nodiscard]] FactoryQueueItemMismatch FindFirstBuildQueueItemMismatch(
    const FactoryQueueItem* const first1,
    const FactoryQueueItem* const last1,
    const FactoryQueueItem* const first2
  )
  {
    const FactoryQueueItem* leftCursor = first1;
    const FactoryQueueItem* rightCursor = first2;
    while (leftCursor != last1) {
      if (!(leftCursor->blueprintId == rightCursor->blueprintId) || leftCursor->count != rightCursor->count) {
        break;
      }
      ++leftCursor;
      ++rightCursor;
    }
    return FactoryQueueItemMismatch{leftCursor, rightCursor};
  }

  /**
   * Address: 0x00837750 (FUN_00837750, sub_837750)
   *
   * IDA signature:
   * char __usercall sub_837750@<al>(gpg::fastvector_BuildQueueItem *snapshot@<eax>);
   *
   * What it does:
   * Reports whether a freshly-built snapshot already equals the published
   * queue: same row count, and `std::mismatch` reaching the snapshot end.
   */
  [[nodiscard]] bool IsBuildQueueSnapshotUnchanged(
    const moho::FactoryQueueDisplaySnapshot& snapshot
  )
  {
    const FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();
    if (snapshot.size() != currentLanes.size()) {
      return false;
    }

    // FindFirstBuildQueueItemMismatch is the binary's register shape and takes
    // mutable element pointers; both sides are only read.
    auto& mutableSnapshot = const_cast<moho::FactoryQueueDisplaySnapshot&>(snapshot);
    auto& mutableCurrent = const_cast<FactoryQueueLanes&>(currentLanes);
    const FactoryQueueItemMismatch mismatch =
      FindFirstBuildQueueItemMismatch(mutableSnapshot.begin(), mutableSnapshot.end(), mutableCurrent.begin());
    return mismatch.left == mutableSnapshot.end();
  }

  /**
   * Address: 0x00836C80 (FUN_00836C80, sub_836C80)
   *
   * IDA signature:
   * gpg::fastvector_BuildQueueItem *__stdcall sub_836C80(gpg::fastvector_BuildQueueItem *snapshot);
   *
   * What it does:
   * Publishes `snapshot` into the global build queue - the legacy MSVC8
   * `vector<T>::operator=` emission for this element type, with `this` folded to
   * `sCurrentBuildQueue`. Three branches, exactly as the binary: assign over the
   * live prefix and trim (source fits the current size), assign the prefix then
   * uninitialized-copy the tail (source fits the current capacity), or destroy,
   * free, rebuy and uninitialized-copy the whole source.
   */
  moho::FactoryQueueDisplaySnapshot& AssignCurrentBuildQueueFromSnapshot(
    const moho::FactoryQueueDisplaySnapshot& snapshot
  )
  {
    // 0x00836C86 compares the incoming vector against the global's own address.
    if (&snapshot == &moho::sCurrentBuildQueue) {
      return moho::sCurrentBuildQueue;
    }

    FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();

    // The per-type copy adapters below are the binary's register shapes and
    // take mutable element pointers; the source is only read through them.
    auto& mutableSnapshot = const_cast<moho::FactoryQueueDisplaySnapshot&>(snapshot);
    const std::size_t sourceCount = mutableSnapshot.size();
    if (sourceCount == 0u) {
      // 0x00836CB9: erase the whole published queue and keep its buffer.
      FactoryQueueItem* rebasedBegin = nullptr;
      (void)moho::RebaseFactoryQueueRangeAndTrimTail(&rebasedBegin, currentLanes.begin(), currentLanes.end());
      return moho::sCurrentBuildQueue;
    }

    const std::size_t currentCount = currentLanes.size();
    if (sourceCount <= currentCount) {
      // 0x00836D0E: assign over the live prefix, destroy the surplus tail.
      // DeleteRangeBuildQueueItems is explicit because it frees each row's
      // command-id buffer and blueprint-id string, which the element
      // destructor does not.
      FactoryQueueItem* const newEnd =
        CopyBuildQueueItems(currentLanes.begin(), mutableSnapshot.begin(), mutableSnapshot.end());
      DeleteRangeBuildQueueItems(newEnd, currentLanes.end());
      while (currentLanes.size() > sourceCount) {
        currentLanes.pop_back_no_destroy();
      }
      return moho::sCurrentBuildQueue;
    }

    if (sourceCount <= currentLanes.capacity()) {
      // 0x00836DBF: assign over the live rows, then build the extra tail rows
      // into the spare capacity.
      FactoryQueueItem* const sourceSplit = mutableSnapshot.begin() + currentCount;
      (void)CopyBuildQueueItemsThiscallAdapter(sourceSplit, mutableSnapshot.begin(), currentLanes.begin());
      (void)UninitializedCopyBuildQueueItemsAdapter(sourceSplit, mutableSnapshot.end(), currentLanes.end());
      while (currentLanes.size() < sourceCount) {
        currentLanes.push_back_no_construct();
      }
      return moho::sCurrentBuildQueue;
    }

    // 0x00836DEC: capacity is short - destroy, free, rebuy, rebuild.
    if (!currentLanes.empty()) {
      DeleteRangeBuildQueueItemsThiscallAdapter(currentLanes.end(), currentLanes.begin());
    }

    if (AllocateBuildQueueStorage(currentLanes, static_cast<std::uint32_t>(sourceCount))) {
      (void)UninitializedCopyBuildQueueItemsAdapter(
        mutableSnapshot.begin(), mutableSnapshot.end(), currentLanes.begin()
      );
      while (currentLanes.size() < sourceCount) {
        currentLanes.push_back_no_construct();
      }
    }
    return moho::sCurrentBuildQueue;
  }
}


/**
 * Address: 0x00837070 (FUN_00837070, sub_837070)
 *
 * IDA signature:
 * struct_BuildQueueItem **__stdcall sub_837070(struct_BuildQueueItem **a1,
 *                                              struct_BuildQueueItem *result,
 *                                              struct_BuildQueueItem *src);
 *
 * What it does:
 * Compacts the published queue window by assigning the half-open tail
 * `[sourceBegin, sCurrentBuildQueue end)` down onto `destinationBegin`,
 * destroying the vacated tail and republishing `_Mylast`. Callers that pass
 * `(_Myfirst, _Mylast)` use it as the queue's erase-all lane.
 */
moho::FactoryQueueDisplayItem** moho::RebaseFactoryQueueRangeAndTrimTail(
  FactoryQueueDisplayItem** const outBegin,
  FactoryQueueDisplayItem* const destinationBegin,
  FactoryQueueDisplayItem* const sourceBegin
)
{
  FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();
  if (destinationBegin != sourceBegin) {
    // Shift the survivors down over [destinationBegin, sourceBegin), destroy
    // the vacated tail and rebase mLast: erase(first, last). The explicit
    // DeleteRangeBuildQueueItems stays because it also frees each row's
    // command-id buffer and blueprint-id string, which the element destructor
    // does not.
    FactoryQueueDisplayItem* const newEnd = CopyBuildQueueItems(destinationBegin, sourceBegin, currentLanes.end());
    DeleteRangeBuildQueueItems(newEnd, currentLanes.end());
    while (currentLanes.end() != newEnd) {
      currentLanes.pop_back_no_destroy();
    }
  }

  *outBegin = destinationBegin;
  return outBegin;
}

/**
 * Address: 0x00836180 (FUN_00836180)
 * Mangled: ?UI_FactoryCommandQueueHandlerBeat@Moho@@YAXXZ
 *
 * IDA signature:
 * void __cdecl Moho::UI_FactoryCommandQueueHandlerBeat();
 *
 * What it does:
 * Per-beat refresh of the factory build-queue mirror. While a factory is bound,
 * rebuilds a stack-local snapshot of its queue through a temporary weak link and
 * - when the snapshot differs from what is published - builds the Lua queue
 * table, republishes the snapshot, and calls
 * `/lua/ui/game/gamemain.lua:OnQueueChanged` with it. Once the factory is gone,
 * erases the published queue and fires the same callback with `nil`.
 */
void moho::UI_FactoryCommandQueueHandlerBeat()
{
  LuaPlus::LuaState* const state = ResolveUiManagerLuaState();

  LuaPlus::LuaObject queueTable;
  bool queueChanged = true;

  if (sCurrentBuildFactory.GetObjectPtr() != nullptr) {
    FactoryQueueDisplaySnapshot snapshot;

    // 0x008361DC..0x008361F9 build a temporary weak node onto the same owner
    // chain and hand it to the rebuild worker by value.
    WeakPtr<UserUnit> factoryLink(sCurrentBuildFactory);

    RebuildFactoryQueueDisplaySnapshot(snapshot, factoryLink);

    if (IsBuildQueueSnapshotUnchanged(snapshot)) {
      queueChanged = false;
    } else {
      BuildFactoryQueueLuaTable(snapshot, state, &queueTable);
      (void)AssignCurrentBuildQueueFromSnapshot(snapshot);
    }
    // 0x0083622E tears the snapshot down: destroy the rows, free the buffer.
  } else {
    // 0x008362EC: no factory bound. Nothing to announce unless a queue is still
    // published.
    FactoryQueueLanes& currentLanes = CurrentBuildQueueLanes();
    if (currentLanes.empty()) {
      return;
    }

    queueTable.AssignNil(state);
    FactoryQueueDisplayItem* rebasedBegin = nullptr;
    (void)RebaseFactoryQueueRangeAndTrimTail(&rebasedBegin, currentLanes.begin(), currentLanes.end());
  }

  if (!queueChanged) {
    return;
  }

  try {
    const LuaPlus::LuaObject moduleObject = SCR_Import(state, kFactoryQueueChangedModule);
    const LuaPlus::LuaObject callbackObject = moduleObject[kFactoryQueueChangedCallback];
    LuaPlus::LuaFunction<void> callbackFunction(callbackObject);
    callbackFunction(queueTable);
  } catch (const std::exception& exception) {
    gpg::Warnf(kFactoryQueueChangedWarning, exception.what() != nullptr ? exception.what() : "");
  }
}
