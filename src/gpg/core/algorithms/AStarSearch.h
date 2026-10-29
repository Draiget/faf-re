#pragma once

/**
 * `gpgcore/algorithms/AStarSearch.h` - the engine's generic A* search, recovered
 * from the Forged Alliance binary.
 *
 * The original header path is named by the assertion strings the search itself
 * raises ("node.mState == CLOSED" at line 195, "neib->mState == CLOSED" at line
 * 253, both citing `c:\work\rts\main\code\src\libs\gpgcore/algorithms/AStarSearch.h`),
 * which is what fixes this file's location and confirms the code was a template
 * shared beyond the pathfinder.
 *
 * The search keeps two structures:
 *
 *   - a node table keyed by cell (`msvc8::hash_map`), holding the per-cell
 *     search record; and
 *   - an *indexed* binary heap of open nodes. "Indexed" because callers hold a
 *     stable handle rather than a heap position: `mIndexByHandle` maps a handle
 *     to the entry's current slot and is kept in sync by every sift, so an
 *     already-open node can be re-prioritised in O(log n) without a scan.
 *     Released handles are recycled through a freelist threaded in place
 *     (`mFreeHandle` heads a chain stored in the vacated index slots).
 *
 * Layout is ABI-pinned by `Moho::PathQueue::ImplBase`, which derives from this
 * template: the node table occupies +0x00..+0x28 and the open heap
 * +0x28..+0x4C, leaving the derived class's own state to start at +0x4C.
 */

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/FlatGenerationMap.h"
#include "legacy/containers/HashMap.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
    /**
     * Per-cell visitation state.
     *
     * The binary encodes these as the raw values 0/1/2 and asserts that no
     * other value can reach the relaxation paths.
     */
    enum class AStarNodeState : std::int32_t
    {
        Unvisited = 0,
        Open = 1,
        Closed = 2,
    };

    /**
     * One search record. Stored by value inside the node table, so its address
     * is stable for as long as the entry lives - which is what lets `mParent`
     * and the heap entries hold raw pointers to it.
     */
    template <class TCell>
    struct AStarNode
    {
        TCell mCell;                // +0x00
        AStarNodeState mState;      // +0x04
        AStarNode* mParent;         // +0x08
        float mCost;                // +0x0C  cost from the start cell
        float mEstimate;            // +0x10  heuristic remainder to the goal
        std::int32_t mHandle;       // +0x14  open-heap handle, valid while Open

        AStarNode()
            : mCell()
            , mState(AStarNodeState::Unvisited)
            , mParent(nullptr)
            , mCost(0.0f)
            , mEstimate(0.0f)
            , mHandle(0)
        {
        }
    };

    /**
     * Min-heap of open nodes ordered by `mCost + mEstimate`, with stable
     * caller-visible handles.
     *
     * Layout (relative to the heap, which lives at `AStarSearch` +0x28):
     *   +0x00 : mEntries        (msvc8::vector, 4 words)
     *   +0x10 : mIndexByHandle  (msvc8::vector, 4 words)
     *   +0x20 : mFreeHandle
     *   sizeof == 0x24
     */
    template <class TCell>
    class AStarOpenHeap
    {
    public:
        using node_type = AStarNode<TCell>;

        /**
         * One heap slot. `mHandle` is the back-reference used to repair
         * `mIndexByHandle` whenever the entry is moved by a sift.
         */
        struct Entry
        {
            float mPriority;      // +0x00
            node_type* mNode;     // +0x04
            std::int32_t mHandle; // +0x08
        };

    private:
        msvc8::vector<Entry> mEntries;              // +0x00
        msvc8::vector<std::int32_t> mIndexByHandle; // +0x10
        std::int32_t mFreeHandle;                   // +0x20

    public:
        AStarOpenHeap()
            : mFreeHandle(-1)
        {
        }

        [[nodiscard]] bool empty() const noexcept { return mEntries.size() == 0; }
        [[nodiscard]] std::size_t size() const noexcept { return mEntries.size(); }

        /** The lowest-priority open node. Only valid while the heap is non-empty. */
        [[nodiscard]] node_type* top() const noexcept { return mEntries[0].mNode; }

        /**
         * Address: 0x007672E0 (FUN_007672E0, first half)
         *
         * What it does:
         * Drops every open entry and every live handle, returning the heap to
         * its freshly-constructed state.
         */
        void clear()
        {
            mEntries.clear();
            mIndexByHandle.clear();
            mFreeHandle = -1;
        }

        /**
         * Address: 0x00768FF0 (FUN_00768FF0)
         *
         * IDA signature:
         * int __userpurge sub_768FF0@<eax>(std::vector *a1@<edi>, __int64 a2);
         *
         * What it does:
         * Appends one entry at the end of the heap array, allocates a handle
         * pointing at that slot, then restores the heap property by sifting the
         * new entry upward. Returns the handle.
         */
        std::int32_t Push(float priority, node_type* node)
        {
            const std::size_t insertedAt = mEntries.size();
            const std::int32_t handle = AllocateHandle(static_cast<std::int32_t>(insertedAt));

            Entry entry;
            entry.mPriority = priority;
            entry.mNode = node;
            entry.mHandle = handle;
            mEntries.push_back(entry);

            SiftUp(insertedAt);
            return handle;
        }

        /**
         * Address: 0x007697E0 (FUN_007697E0)
         *
         * IDA signature:
         * int __usercall sub_7697E0@<eax>(_DWORD *a1@<eax>);
         *
         * What it does:
         * Removes the root entry by swapping it with the last slot, sifting the
         * displaced entry down over the shortened range, recycling the removed
         * entry's handle onto the freelist, and shrinking the array.
         */
        std::size_t Pop()
        {
            const std::size_t count = mEntries.size();
            if (count == 0) {
                return 0;
            }

            const std::size_t lastIndex = count - 1;
            if (count != 1) {
                SwapEntries(lastIndex, 0);
                SiftDown(0, lastIndex);
            }

            const std::int32_t releasedHandle = mEntries[lastIndex].mHandle;
            mIndexByHandle[static_cast<std::size_t>(releasedHandle)] = mFreeHandle;
            mFreeHandle = releasedHandle;

            mEntries.resize(lastIndex);
            return lastIndex;
        }

        /**
         * Address: 0x00769060 (FUN_00769060)
         *
         * IDA signature:
         * unsigned int __usercall sub_769060@<eax>(_DWORD *a1@<eax>, int a2@<ecx>, float a3@<xmm0>);
         *
         * What it does:
         * Re-prioritises the entry behind `handle` in place, then restores the
         * heap property in whichever direction the change moved it.
         */
        void UpdatePriority(std::int32_t handle, float priority)
        {
            const std::size_t index = static_cast<std::size_t>(mIndexByHandle[static_cast<std::size_t>(handle)]);
            const float previous = mEntries[index].mPriority;
            mEntries[index].mPriority = priority;

            if (previous > priority) {
                SiftUp(index);
            } else {
                SiftDown(index, mEntries.size());
            }
        }

    private:
        /**
         * Address: 0x00769780 (FUN_00769780)
         *
         * What it does:
         * Returns a handle whose index slot now holds `index`, reusing the head
         * of the freelist when one is available and appending a fresh slot
         * otherwise. The freelist is threaded through the vacated slots
         * themselves, so recycling costs no extra storage.
         */
        std::int32_t AllocateHandle(std::int32_t index)
        {
            if (mFreeHandle == -1) {
                const std::int32_t handle = static_cast<std::int32_t>(mIndexByHandle.size());
                mIndexByHandle.push_back(index);
                return handle;
            }

            const std::int32_t handle = mFreeHandle;
            mFreeHandle = mIndexByHandle[static_cast<std::size_t>(handle)];
            mIndexByHandle[static_cast<std::size_t>(handle)] = index;
            return handle;
        }

        /**
         * Address: 0x00769C30 (FUN_00769C30)
         *
         * What it does:
         * Exchanges two heap slots and repoints both handles at their new
         * positions, keeping `mIndexByHandle` authoritative.
         */
        void SwapEntries(std::size_t firstIndex, std::size_t secondIndex)
        {
            Entry& first = mEntries[firstIndex];
            Entry& second = mEntries[secondIndex];

            const Entry saved = first;
            first = second;
            second = saved;

            mIndexByHandle[static_cast<std::size_t>(first.mHandle)] = static_cast<std::int32_t>(firstIndex);
            mIndexByHandle[static_cast<std::size_t>(second.mHandle)] = static_cast<std::int32_t>(secondIndex);
        }

        /**
         * Address: 0x00769600 (FUN_00769600)
         *
         * IDA signature:
         * unsigned int callcnv_F3 sub_769600@<eax>(unsigned int result@<eax>, int a2@<ebx>);
         *
         * What it does:
         * Walks one entry toward the root while it outranks its parent,
         * swapping as it goes.
         */
        void SiftUp(std::size_t index)
        {
            while (index != 0) {
                const std::size_t parent = (index - 1) / 2;
                if (mEntries[index].mPriority > mEntries[parent].mPriority) {
                    break;
                }
                SwapEntries(parent, index);
                index = parent;
            }
        }

        /**
         * Address: 0x007696A0 (FUN_007696A0)
         *
         * IDA signature:
         * unsigned int callcnv_E3 sub_7696A0@<eax>(unsigned int a1@<eax>, int a2@<edi>, unsigned int a3);
         *
         * What it does:
         * Walks one entry toward the leaves, repeatedly trading places with its
         * smaller child until neither child outranks it. `count` bounds the live
         * range, which is how `Pop` sifts over the array minus its last slot.
         */
        void SiftDown(std::size_t index, std::size_t count)
        {
            for (;;) {
                const std::size_t left = 2 * index + 1;
                if (left >= count) {
                    break;
                }

                std::size_t smallest = index;
                if (mEntries[index].mPriority > mEntries[left].mPriority) {
                    smallest = left;
                }

                const std::size_t right = left + 1;
                if (right < count && mEntries[smallest].mPriority > mEntries[right].mPriority) {
                    smallest = right;
                }

                if (smallest == index) {
                    break;
                }

                SwapEntries(index, smallest);
                index = smallest;
            }
        }
    };

    /** One edge offered by the owner's expansion: where to, and at what cost. */
    template <class TCell>
    struct AStarNeighbour
    {
        TCell mCell;  // +0x00
        float mCost;  // +0x04
    };

    /**
     * The A* search state shared by every instantiation.
     *
     * `TTraits` is the enclosing search owner (CRTP): the binary passes the same
     * pointer twice at every call site (`push edi; push edi` at 0x00765F36),
     * because the traits object *is* the derived search object. Owners supply:
     *
     *   float GetHeuristicCost(const TCell&) const;
     *   void  NoteCandidateCell(const TCell&, float estimate);
     *   Step  ExpandNode(const TCell&, neighbour_list&);  // Step{} = keep going
     *
     * Layout:
     *   +0x00 : mNodes  (msvc8::hash_map, 0x28; AStarNodeTable keeps the size)
     *   +0x28 : mOpen   (AStarOpenHeap, 0x24)
     *   sizeof == 0x4C
     */
    /** False with `/astartable 0` or FAF_ASTARTABLE=0: A* keeps the binary's hash_map node table. */
    [[nodiscard]] bool AStarFlatNodeTableEnabled() noexcept;

    /**
     * Engine addition: the A* node table as a FlatGenerationMap from the
     * cell's 32-bit key to a node in a pool allocated in chunks, so node
     * addresses stay fixed while a query runs, as the parent links and heap
     * entries require. Clearing bumps the map's generation and rewinds the
     * pool instead of freeing every node, which the binary's table does after
     * each query.
     *
     * The search only finds and inserts by cell and never walks the table, so
     * any table that gives the same answers gives the same paths.
     */
    template <class TCell, class TNode>
    class AStarFlatNodeTable
    {
        static_assert(sizeof(TCell) == sizeof(std::uint32_t), "the cell is its own 32-bit key");

    public:
        [[nodiscard]] TNode* Find(const TCell& cell) noexcept
        {
            TNode* const* const found = mIndex.Find(Key(cell));
            return (found != nullptr) ? *found : nullptr;
        }

        /** Adds an unvisited node for `cell`, which must not be in the table. */
        [[nodiscard]] TNode& Insert(const TCell& cell)
        {
            if (mPoolUsed == mChunks.size() * kChunkNodes) {
                mChunks.push_back(std::make_unique<TNode[]>(kChunkNodes));
            }
            TNode* const node = &mChunks[mPoolUsed / kChunkNodes][mPoolUsed % kChunkNodes];
            ++mPoolUsed;
            *node = TNode();
            node->mCell = cell;
            (void)mIndex.Insert(Key(cell), node);
            return *node;
        }

        void Clear() noexcept
        {
            mPoolUsed = 0;
            mIndex.Clear();
        }

    private:
        static constexpr std::size_t kChunkNodes = 1024;

        [[nodiscard]] static std::uint32_t Key(const TCell& cell) noexcept
        {
            std::uint32_t key;
            std::memcpy(&key, &cell, sizeof(key));
            return key;
        }

        core::FlatGenerationMap<TNode*> mIndex;
        std::vector<std::unique_ptr<TNode[]>> mChunks;
        std::size_t mPoolUsed = 0;
    };

    /**
     * The search's node table: the binary's `msvc8::hash_map` in place, or, for
     * a search that allows it and with AStarFlatNodeTableEnabled(), a pointer
     * to the flat table in the same bytes, which keeps `AStarSearch`'s layout.
     * The choice is made once per process, so every table is read the way it
     * was built.
     */
    template <class TCell, class TNode, class TCellTraits, bool kAllowFlat>
    class AStarNodeTable
    {
        using legacy_type = msvc8::hash_map<TCell, TNode, TCellTraits>;
        using flat_type = AStarFlatNodeTable<TCell, TNode>;

        [[nodiscard]] static bool UseFlat() noexcept
        {
            if constexpr (kAllowFlat) {
                static_assert(sizeof(flat_type*) <= sizeof(legacy_type), "the flat table's pointer fits the hash_map's bytes");
                return AStarFlatNodeTableEnabled();
            } else {
                return false;
            }
        }

    public:
        AStarNodeTable()
        {
            if constexpr (kAllowFlat) {
                if (UseFlat()) {
                    ::new (static_cast<void*>(mStorage)) flat_type*(new flat_type());
                    return;
                }
            }
            ::new (static_cast<void*>(mStorage)) legacy_type();
        }

        ~AStarNodeTable()
        {
            if constexpr (kAllowFlat) {
                if (UseFlat()) {
                    delete Flat();
                    return;
                }
            }
            Legacy().~legacy_type();
        }

        AStarNodeTable(const AStarNodeTable&) = delete;
        AStarNodeTable& operator=(const AStarNodeTable&) = delete;

        [[nodiscard]] TNode* Find(const TCell& cell)
        {
            if constexpr (kAllowFlat) {
                if (UseFlat()) {
                    return Flat()->Find(cell);
                }
            }
            const typename legacy_type::iterator found = Legacy().find(cell);
            return (found != Legacy().end()) ? &found->second : nullptr;
        }

        /** Address: 0x00768F40 (FUN_00768F40) on the binary's table. */
        [[nodiscard]] TNode& FindOrCreate(const TCell& cell)
        {
            if constexpr (kAllowFlat) {
                if (UseFlat()) {
                    flat_type* const flat = Flat();
                    TNode* const found = flat->Find(cell);
                    return (found != nullptr) ? *found : flat->Insert(cell);
                }
            }
            const typename legacy_type::iterator found = Legacy().find(cell);
            if (found != Legacy().end()) {
                return found->second;
            }
            TNode fresh;
            fresh.mCell = cell;
            return Legacy().insert(typename legacy_type::value_type(cell, fresh)).first->second;
        }

        void clear()
        {
            if constexpr (kAllowFlat) {
                if (UseFlat()) {
                    Flat()->Clear();
                    return;
                }
            }
            Legacy().clear();
        }

    private:
        [[nodiscard]] legacy_type& Legacy() noexcept { return *std::launder(reinterpret_cast<legacy_type*>(mStorage)); }
        [[nodiscard]] flat_type* Flat() const noexcept
        {
            return *std::launder(reinterpret_cast<flat_type* const*>(mStorage));
        }

        alignas(legacy_type) unsigned char mStorage[sizeof(legacy_type)];
    };

    template <class TCell, class TTraits, class TCellTraits = msvc8::hash_compare<TCell>, bool kAllowFlatTable = false>
    class AStarSearch
    {
    public:
        using node_type = AStarNode<TCell>;
        using table_type = AStarNodeTable<TCell, node_type, TCellTraits, kAllowFlatTable>;
        using heap_type = AStarOpenHeap<TCell>;
        using neighbour_type = AStarNeighbour<TCell>;

        // The expansion buffer lives on the search's stack frame: 200 inline
        // entries before it spills to the heap (the 0x10 head at [esp+650h],
        // entries at [esp+660h]..[esp+CA0h] in 0x007685A0).
        using neighbour_list = core::FastVectorN<neighbour_type, 200>;

    protected:
        table_type mNodes;  // +0x00
        heap_type mOpen;    // +0x28

    public:
        AStarSearch() = default;

        [[nodiscard]] table_type& Nodes() noexcept { return mNodes; }
        [[nodiscard]] heap_type& OpenSet() noexcept { return mOpen; }

        /**
         * Address: 0x007672E0 (FUN_007672E0) + 0x007676A0 / 0x00767C70
         *
         * What it does:
         * Returns the search to its initial state so the owner can start a new
         * query without reallocating either structure.
         */
        void ResetSearch()
        {
            mOpen.clear();
            mNodes.clear();
        }

        /**
         * Address: 0x00768F40 (FUN_00768F40)
         *
         * IDA signature:
         * int __usercall sub_768F40@<eax>(int *eax0@<eax>, _DWORD *a2@<ecx>);
         *
         * What it does:
         * Returns the search record for `cell`, creating a default (unvisited)
         * record when the cell has not been reached yet.
         */
        [[nodiscard]] node_type& FindOrCreateNode(const TCell& cell)
        {
            return mNodes.FindOrCreate(cell);
        }

        /**
         * Address: 0x007684C0 (FUN_007684C0)
         *
         * IDA signature:
         * void __userpurge sub_7684C0(int *a1@<eax>, int ebx0@<ebx>, _DWORD *a3);
         *
         * What it does:
         * Seeds `cell` as a zero-cost origin. An unvisited cell is opened with
         * its heuristic as priority; an already-open cell that was reached at a
         * non-zero cost is re-rooted to cost zero and re-prioritised. A closed
         * cell is left alone - reopening it would violate the search invariant,
         * which is exactly what the binary's assertion guards.
         */
        void AddStartNode(const TCell& cell, TTraits& traits)
        {
            node_type& node = FindOrCreateNode(cell);

            switch (node.mState) {
                case AStarNodeState::Unvisited: {
                    node.mState = AStarNodeState::Open;

                    const float estimate = traits.GetHeuristicCost(cell);
                    traits.NoteCandidateCell(cell, estimate);

                    node.mEstimate = estimate;
                    node.mParent = nullptr;
                    node.mCell = cell;
                    node.mCost = 0.0f;
                    node.mHandle = mOpen.Push(estimate, &node);
                    break;
                }

                case AStarNodeState::Open: {
                    if (node.mCost > 0.0f) {
                        node.mParent = nullptr;
                        node.mCost = 0.0f;
                        node.mCell = cell;
                        mOpen.UpdatePriority(node.mHandle, node.mEstimate);
                    }
                    break;
                }

                case AStarNodeState::Closed:
                default:
                    // "node.mState == CLOSED", AStarSearch.h:195
                    assert(node.mState == AStarNodeState::Closed);
                    break;
            }
        }

        /**
         * Address: 0x00768940 (FUN_00768940)
         *
         * IDA signature:
         * char callcnv_E3 sub_768940@<al>(Moho::PathQueue::ImplBase *a1@<eax>, int *a2@<ecx>, std::vector *a3);
         *
         * What it does:
         * Materialises the parent chain ending at `cell` into `outCells`, in
         * start-to-goal order. Reports false when the cell was never reached.
         *
         * The chain is counted before the output is sized so the cells can be
         * written back-to-front in a single pass - the binary does the same, and
         * it avoids reversing afterwards.
         */
        [[nodiscard]] bool BuildPath(const TCell& cell, msvc8::vector<TCell>& outCells)
        {
            node_type* const goal = mNodes.Find(cell);
            if (goal == nullptr) {
                return false;
            }

            std::size_t length = 0;
            for (const node_type* step = goal; step != nullptr; step = step->mParent) {
                ++length;
            }

            outCells.resize(length, TCell());

            std::size_t writeIndex = length;
            for (const node_type* step = goal; step != nullptr; step = step->mParent) {
                outCells[--writeIndex] = step->mCell;
            }
            return true;
        }

        /**
         * Address: 0x007685A0 (FUN_007685A0, the `Moho::PathQueue::ImplBase`
         * instantiation; callers 0x00765DD0, 0x00765ED0, 0x007660C0)
         *
         * IDA signature:
         * int __stdcall sub_7685A0(Moho::PathQueue::ImplBase *a3, Moho::PathQueue::ImplBase *a2);
         *
         * What it does:
         * The A* main loop. Each pass takes the cheapest open node and asks the
         * owner to expand it; a non-default step from the owner ends the pass
         * and is returned (goal reached, budget spent, ...). Otherwise the node
         * closes and every offered edge relaxes its target: an unvisited target
         * opens with its heuristic, an open one re-parents when this route is
         * cheaper. Returns the default step only once the open set is empty,
         * i.e. nothing further is reachable.
         */
        auto WorkOnce(TTraits& traits)
        {
            using step_type = decltype(traits.ExpandNode(std::declval<const TCell&>(), std::declval<neighbour_list&>()));

            neighbour_list neighbours;

            while (!mOpen.empty()) {
                node_type* const current = mOpen.top();

                neighbours.clear();
                const step_type step = traits.ExpandNode(current->mCell, neighbours);
                if (step != step_type{}) {
                    return step;
                }

                current->mState = AStarNodeState::Closed;
                (void)mOpen.Pop();

                for (const neighbour_type& neighbour : neighbours) {
                    node_type& node = FindOrCreateNode(neighbour.mCell);
                    const float reachedCost = current->mCost + neighbour.mCost;

                    switch (node.mState) {
                        case AStarNodeState::Unvisited: {
                            node.mState = AStarNodeState::Open;

                            const float estimate = traits.GetHeuristicCost(neighbour.mCell);
                            traits.NoteCandidateCell(neighbour.mCell, estimate);

                            node.mEstimate = estimate;
                            node.mParent = current;
                            node.mCell = neighbour.mCell;
                            node.mCost = reachedCost;
                            node.mHandle = mOpen.Push(reachedCost + estimate, &node);
                            break;
                        }

                        case AStarNodeState::Open: {
                            // Only a genuinely cheaper route re-parents; the
                            // estimate is unchanged, so this is a decrease-key.
                            if (node.mCost > reachedCost) {
                                node.mParent = current;
                                node.mCell = neighbour.mCell;
                                node.mCost = reachedCost;
                                mOpen.UpdatePriority(node.mHandle, node.mEstimate + reachedCost);
                            }
                            break;
                        }

                        case AStarNodeState::Closed:
                        default:
                            // "neib->mState == CLOSED", AStarSearch.h:253
                            assert(node.mState == AStarNodeState::Closed);
                            break;
                    }
                }
            }

            return step_type{};
        }
    };
} // namespace gpg
