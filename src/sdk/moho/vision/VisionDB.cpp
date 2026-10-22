#include "moho/vision/VisionDB.h"

#include <algorithm>
#include <cmath>
#include <span>
#include <unordered_map>
#include <vector>

#include "Wm3IntrBox2Circle2.h"
#include "moho/app/UserWorkerPool.h"

using namespace moho;

namespace
{
  /**
   * Whether `outer` encloses `inner` completely: the radius first, then the
   * squared center distance against the squared radius difference. The
   * binary keeps an uncalled out-of-line copy at 0x0081A7F0; `Entry::Contains`
   * inlines it once per circle.
   */
  [[nodiscard]] bool CircleContains(const Wm3::Circle2f& outer, const Wm3::Circle2f& inner) noexcept
  {
    if (inner.Radius > outer.Radius) {
      return false;
    }

    const float dx = inner.Center.x - outer.Center.x;
    const float dy = inner.Center.y - outer.Center.y;
    const float radiusDelta = outer.Radius - inner.Radius;
    return (radiusDelta * radiusDelta) >= ((dx * dx) + (dy * dy));
  }

  /**
   * The circle `t` of the way from `from` to `to`, componentwise. The binary
   * keeps an uncalled out-of-line copy at 0x0081A840; `VisionDB::TryAdd`
   * inlines it.
   */
  [[nodiscard]] Wm3::Circle2f InterpolateCircle(const Wm3::Circle2f& from, const Wm3::Circle2f& to, const float t) noexcept
  {
    return Wm3::Circle2f{
      Wm3::Vector2f{from.Center.x + ((to.Center.x - from.Center.x) * t), from.Center.y + ((to.Center.y - from.Center.y) * t)},
      ((to.Radius - from.Radius) * t) + from.Radius
    };
  }

  enum class EVisionEntryResult
  {
    Outside,
    Circle,
    Descend,
  };

  /**
   * One step of `VisionDB::TryAdd`: interpolate the entry's circle, test it against `box`, and say
   * whether it is outside, contributes its circle (real, visible emitter), or hands over to the
   * entries it contains.
   */
  [[nodiscard]] EVisionEntryResult EvaluateVisionEntry(
    const VisionDB::Entry& entry, const Wm3::Box2f& box, const float interpolant, Wm3::Circle2f& sampled
  )
  {
    sampled = InterpolateCircle(entry.mPrevCircle, entry.mCurCircle, interpolant);

    // `Wm3::IntrBox2Circle2f` keeps references to both operands, so `box` and
    // `sampled` must outlive it - matching the two stack temporaries the binary
    // builds at 0x0081B4F2/0x0081B504 before the ctor call at 0x0081B52C.
    Wm3::IntrBox2Circle2f overlap{box, sampled};
    if (!overlap.Test()) {
      return EVisionEntryResult::Outside;
    }
    return (entry.mIsReal && entry.mVisible) ? EVisionEntryResult::Circle : EVisionEntryResult::Descend;
  }

  /// `VisionDB::TryAdd`'s depth-first walk, into any vector-like accumulator.
  template <class Accumulator>
  void AccumulateVisibleCircles(
    Accumulator& accumulator, const VisionDB::Entry* const entry, const Wm3::Box2f& box, const float interpolant
  )
  {
    Wm3::Circle2f sampled{};
    switch (EvaluateVisionEntry(*entry, box, interpolant, sampled)) {
      case EVisionEntryResult::Outside:
        return;
      case EVisionEntryResult::Circle:
        accumulator.push_back(sampled);
        return;
      case EVisionEntryResult::Descend:
        for (const VisionDB::Entry* child = entry->mContained; child != nullptr; child = child->mNext) {
          AccumulateVisibleCircles(accumulator, child, box, interpolant);
        }
        return;
    }
  }

  // Parallel fog-of-war collection: expand the top of the tree until there are this many
  // independent subtrees, and run them in chunks of this many.
  constexpr std::size_t kVisionParallelMinSubtrees = 64u;
  constexpr std::size_t kVisionParallelTargetSubtrees = 512u;
  constexpr std::size_t kVisionParallelGrain = 32u;
  constexpr int kVisionParallelMaxExpandDepth = 8;

  /**
   * Engine addition (`ren_ParallelCull`): counts structural edits of the vision trees - a link
   * added or removed, an entry freed, a tree built or torn down. The fog pass keeps array copies of
   * the top chains of the tree while this count is unchanged, so it can hand their entries to the
   * user workers without walking the linked chains on the main thread every frame.
   */
  std::uint64_t gVisionTreeEdits = 0u;

  void NoteVisionTreeEdit() noexcept
  {
    ++gVisionTreeEdits;
  }

  /**
   * Engine addition (`ren_GpuFog`): counts changes of an emitter's circles or visibility
   * (`Handle::Update` with new values). With `gVisionTreeEdits` it tells the GPU fog pass whether
   * its collected emitters (`VisionDB::CollectEmitters`) are still current. Every writer runs on
   * the main thread (the serial half of the sync apply).
   */
  std::uint64_t gVisionEntryEdits = 0u;

  /**
   * Engine addition: shortcuts for the two linear walks the chains need. A chain is singly linked
   * and the binary walks it to the tail on every append (`AddToChain`) and to the predecessor on
   * every unlink (`RemoveFromChain`), so with thousands of emitters under one node every new
   * entity paid thousands of steps (a quarter of the main thread in a 2k vs 2k air fight).
   *
   * These are hints only. Each is checked before use - a tail must still belong to the same parent
   * and end its chain, a predecessor must still link to the node - and a stale or missing hint
   * falls back to the original walk, so the tree comes out exactly as the binary builds it. Only
   * the main thread edits the tree (the serial half of the sync apply).
   */
  std::unordered_map<const VisionDB::Entry*, VisionDB::Entry*> gChainTails; // parent -> last node it contains
  std::unordered_map<const VisionDB::Entry*, VisionDB::Entry*> gChainPrevious; // node -> node linking to it

  /**
   * Engine addition: the last entry `NewHandle` put in the tree, and the edit counts right after.
   * Every new handle starts as two zero circles at the origin, and a fake unit (a recon blip)
   * gets a fresh one on each data update and drops it again in its tick. So within one sync apply
   * thousands of identical zero entries pile up, each one nested inside the previous: the walk
   * from the root was a thousand levels deep. While nothing at all has changed in the trees since
   * the previous insertion, an identical entry takes exactly the path the previous one took and
   * then goes into it as its first child, so `NewHandle` puts it there directly.
   */
  struct SLastNewEntry
  {
    const VisionDB* mDb = nullptr;
    VisionDB::Entry* mEntry = nullptr;
    std::uint64_t mTreeEdits = 0u;
    std::uint64_t mEntryEdits = 0u;
  };
  SLastNewEntry gLastNewEntry;

  void ForgetChainHints() noexcept
  {
    gChainTails.clear();
    gChainPrevious.clear();
    gLastNewEntry = SLastNewEntry{};
  }

  /// The last node of the chain `parent` contains, from the hint when it is still true.
  [[nodiscard]] VisionDB::Entry* ChainTailHint(const VisionDB::Entry* const parent) noexcept
  {
    if (parent == nullptr) {
      return nullptr;
    }
    const auto it = gChainTails.find(parent);
    if (it == gChainTails.end() || it->second->mParent != parent || it->second->mNext != nullptr) {
      return nullptr;
    }
    return it->second;
  }

  /// The node of `parent`'s chain that links to `entry`, from the hint when it is still true.
  [[nodiscard]] VisionDB::Entry* ChainPreviousHint(const VisionDB::Entry* const parent, const VisionDB::Entry* const entry) noexcept
  {
    const auto it = gChainPrevious.find(entry);
    if (it == gChainPrevious.end() || it->second->mNext != entry || it->second->mParent != parent) {
      return nullptr;
    }
    return it->second;
  }

  [[nodiscard]] bool SameCircle(const Wm3::Circle2f& lhs, const Wm3::Circle2f& rhs) noexcept
  {
    return lhs.Center.x == rhs.Center.x && lhs.Center.y == rhs.Center.y && lhs.Radius == rhs.Radius;
  }

  /**
   * Engine addition (`ren_ParallelCull`): array copies of the chains under a tree's root and under
   * each of the root's children, in chain order, valid while `gVisionTreeEdits` is unchanged.
   */
  struct VisionTopChains
  {
    const VisionDB* mDb = nullptr;
    const VisionDB::Entry* mRoot = nullptr;
    std::uint64_t mEdits = ~0ull;
    std::vector<const VisionDB::Entry*> mRootChain;
    std::vector<std::vector<const VisionDB::Entry*>> mChildChains; // one per mRootChain entry

    void Refresh(const VisionDB& db, const VisionDB::Entry* const root)
    {
      if (mDb == &db && mRoot == root && mEdits == gVisionTreeEdits) {
        return;
      }
      mDb = &db;
      mRoot = root;
      mEdits = gVisionTreeEdits;
      mRootChain.clear();
      for (const VisionDB::Entry* child = root->mContained; child != nullptr; child = child->mNext) {
        mRootChain.push_back(child);
      }
      if (mChildChains.size() < mRootChain.size()) {
        mChildChains.resize(mRootChain.size());
      }
      for (std::size_t i = 0; i < mRootChain.size(); ++i) {
        std::vector<const VisionDB::Entry*>& chain = mChildChains[i];
        chain.clear();
        for (const VisionDB::Entry* child = mRootChain[i]->mContained; child != nullptr; child = child->mNext) {
          chain.push_back(child);
        }
      }
    }
  };
} // namespace

/**
 * Address: 0x0081AB70 (FUN_0081AB70)
 *
 * What it does:
 * Zeroes the links, both flags and both circles.
 */
VisionDB::Entry::Entry() noexcept
  : mParent(nullptr)
  , mContained(nullptr)
  , mNext(nullptr)
  , mIsReal(false)
  , mVisible(false)
  , mPrevCircle(Wm3::Vector2f{}, 0.0f)
  , mCurCircle(Wm3::Vector2f{}, 0.0f)
{}

bool VisionDB::Entry::Contains(const Entry& other) const noexcept
{
  return CircleContains(mPrevCircle, other.mPrevCircle) && CircleContains(mCurCircle, other.mCurCircle);
}

/**
 * Address: 0x0081A8C0 (FUN_0081A8C0)
 * Address: 0x103E38B0
 *
 * What it does:
 * Appends `entry` after the last node of the chain this node is in; `entry`
 * joins that chain's parent.
 */
void VisionDB::Entry::AddToChain(Entry* const entry) noexcept
{
  // Engine addition: start from the remembered tail (see gChainTails); the walk below then
  // finishes in one step instead of crossing the whole chain.
  Entry* tail = ChainTailHint(mParent);
  if (tail == nullptr) {
    tail = this;
  }
  while (tail->mNext != nullptr) {
    tail = tail->mNext;
  }

  tail->mNext = entry;
  entry->mParent = tail->mParent;
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits

  // Engine addition: `entry` may head a run of nodes (`RemoveFromChain` hands over a contained
  // chain), so the new tail is the end of that run.
  gChainPrevious[entry] = tail;
  if (tail->mParent != nullptr) {
    Entry* last = entry;
    while (last->mNext != nullptr) {
      last = last->mNext;
    }
    gChainTails[tail->mParent] = last;
  }
}

void VisionDB::Entry::AddContained(Entry* const entry) noexcept
{
  // Inlined, the call steps to `mContained->mNext` first and links directly
  // when that is null; same result as walking from `mContained`.
  if (mContained != nullptr) {
    mContained->AddToChain(entry);
    return;
  }

  mContained = entry;
  entry->mParent = this;
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits

  // Engine addition: remember the new chain's tail (see gChainTails).
  Entry* last = entry;
  while (last->mNext != nullptr) {
    last = last->mNext;
  }
  gChainTails[this] = last;
}

/**
 * Address: 0x0081A8E0 (FUN_0081A8E0)
 * Address: 0x103E38D0
 *
 * What it does:
 * Unlinks `entry` from the chain this node contains (`edi` is this node:
 * `[edi+4]` is read as the chain head and `edi` is stored into each moved
 * node's parent). The nodes `entry` contained move up into this node's chain,
 * and `entry` is left with no links.
 */
void VisionDB::Entry::RemoveFromChain(Entry* const entry) noexcept
{
  // Engine addition (see gChainTails): the node linking to `entry`, if it is the tail.
  Entry* newTail = nullptr;
  if (mContained == entry) {
    mContained = entry->mNext;
  } else {
    // Engine addition: the remembered predecessor (see gChainPrevious) replaces the walk when it
    // still links to `entry`.
    Entry* previous = ChainPreviousHint(this, entry);
    if (previous == nullptr) {
      for (Entry* sibling = mContained; sibling != nullptr; sibling = sibling->mNext) {
        if (sibling->mNext == entry) {
          previous = sibling;
          break;
        }
      }
    }
    if (previous != nullptr) {
      previous->mNext = entry->mNext;
      if (entry->mNext != nullptr) {
        gChainPrevious[entry->mNext] = previous;
      } else {
        newTail = previous;
      }
    }
  }
  if (newTail != nullptr) {
    gChainTails[this] = newTail;
  }

  if (entry->mContained != nullptr) {
    AddContained(entry->mContained);
    for (Entry* moved = entry->mContained; moved != nullptr; moved = moved->mNext) {
      moved->mParent = this;
    }
  }

  entry->mParent = nullptr;
  entry->mContained = nullptr;
  entry->mNext = nullptr;
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits
}

void VisionDB::Entry::Remove() noexcept
{
  mParent->RemoveFromChain(this);
}

/**
 * Address: 0x0081B310 (FUN_0081B310, Moho::VisionDB::Entry::PutInChain)
 *
 * What it does:
 * Links this node under the deepest node, starting at `root`, whose circles
 * contain both of its own, or under `root` itself when nothing below it does.
 * The binary re-tests the chosen child at the top of the loop (`jmp 0x81B311`
 * at 0x0081B44C), the shape its tail-recursive source compiles to.
 */
void VisionDB::Entry::PutInChain(Entry* root) noexcept
{
  while (root->Contains(*this)) {
    Entry* child = root->mContained;
    while (child != nullptr && !child->Contains(*this)) {
      child = child->mNext;
    }

    if (child == nullptr) {
      break;
    }
    root = child;
  }

  root->AddContained(this);
}

/**
 * Address: 0x0081ACA0 (FUN_0081ACA0)
 * Mangled: ??0Pool@VisionDB@Moho@@QAE@@Z
 *
 * What it does:
 * Constructs both lists; each buys and self-links its header sentinel.
 */
VisionDB::Pool::Pool()
{
  // Both members buy and self-link their own header sentinel; that is the
  // whole body of 0x0081ACA0, and MSVC emits it.
}

/**
 * Address: 0x0081AD20 (FUN_0081AD20)
 * Address: 0x0081AD00 (FUN_0081AD00, scalar deleting destructor)
 * Address: 0x103E3CA0
 * Address: 0x103E3C80
 *
 * What it does:
 * `delete[]`s every entry block (the vector destructor iterator with the
 * block's stored count at 0x0081AD76, then `operator delete[]` on the
 * cookie); the two lists are destroyed after the body.
 */
VisionDB::Pool::~Pool()
{
  for (Entry* const block : mEntryBlocks) {
    delete[] block;
  }
}

/**
 * Address: 0x0081AA00 (FUN_0081AA00)
 *
 * What it does:
 * Takes the first free entry - allocating a block of 500 and queueing all of
 * them first when the free list is empty - and initialises it with the two
 * circles, the emitter flag, no links and not visible.
 */
VisionDB::Entry*
VisionDB::Pool::NewEntry(const Wm3::Circle2f& previous, const Wm3::Circle2f& current, const bool isReal)
{
  if (mFreeEntries.empty()) {
    Entry* const block = new Entry[kEntriesPerBlock];
    mEntryBlocks.push_back(block);
    for (Entry& entry : std::span{block, kEntriesPerBlock}) {
      mFreeEntries.push_back(&entry);
    }
  }

  Entry* const entry = mFreeEntries.front();
  mFreeEntries.pop_front();

  entry->mParent = nullptr;
  entry->mContained = nullptr;
  entry->mNext = nullptr;
  entry->mIsReal = isReal;
  entry->mVisible = false;
  entry->mPrevCircle = previous;
  entry->mCurCircle = current;
  return entry;
}

/**
 * Address: 0x0081ABF0 (FUN_0081ABF0)
 * Address: 0x103E3B70
 *
 * What it does:
 * Clears the entry's links and both flags (the circles are left as they
 * were) and appends it to the free list.
 */
void VisionDB::Pool::FreeEntry(Entry* const entry)
{
  entry->mParent = nullptr;
  entry->mContained = nullptr;
  entry->mNext = nullptr;
  entry->mIsReal = false;
  entry->mVisible = false;
  mFreeEntries.push_back(entry);
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits
}

/**
 * Address: 0x0081AE10 (FUN_0081AE10)
 *
 * What it does:
 * Stores the owning database and the entry.
 */
VisionDB::Handle::Handle(VisionDB* const db, Entry* const entry) noexcept
  : mDB(db)
  , mEntry(entry)
{}

/**
 * Address: 0x0081AE60 (FUN_0081AE60)
 * Address: 0x0081AE20 (FUN_0081AE20, scalar deleting destructor)
 * Address: 0x103E3DA0
 *
 * What it does:
 * Takes the entry out of the tree and returns it to the database's pool.
 */
VisionDB::Handle::~Handle()
{
  mEntry->Remove();
  mDB->pool_.FreeEntry(mEntry);
}

/**
 * Address: 0x008B83B0 (FUN_008B83B0, Moho::VisionDB::Handle::Update)
 *
 * What it does:
 * Stores the visibility bit and both circles, then moves the entry back down
 * from the root when its parent no longer contains it.
 */
void VisionDB::Handle::Update(
  const Wm3::Vector2f& next,
  const Wm3::Vector2f& previous,
  const float radius,
  const bool visible
)
{
  const Wm3::Circle2f previousCircle{previous, radius};
  const Wm3::Circle2f currentCircle{next, radius};
  // Engine addition, see gVisionEntryEdits.
  if (mEntry->mVisible != visible || !SameCircle(mEntry->mPrevCircle, previousCircle) ||
      !SameCircle(mEntry->mCurCircle, currentCircle)) {
    ++gVisionEntryEdits;
  }

  mEntry->mVisible = visible;
  mEntry->mPrevCircle = previousCircle;
  mEntry->mCurCircle = currentCircle;

  if (!mEntry->mParent->Contains(*mEntry)) {
    mEntry->Remove();
    mEntry->PutInChain(mDB->rootNode_);
  }
}

/**
 * Address: 0x0081AE90 (FUN_0081AE90, sub_81AE90)
 *
 * What it does:
 * Constructs the pool and clears the root.
 */
VisionDB::VisionDB()
  : pool_()
  , rootNode_(nullptr)
{
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits
  ForgetChainHints();   // engine addition, see gChainTails
}

/**
 * Address: 0x0081AF00 (FUN_0081AF00, Moho::VisionDB::Init)
 *
 * What it does:
 * Allocates the root entry covering a circle whose center is `(width/2, height/2)`
 * and bounding radius `2*sqrt((width/2)^2 + (height/2)^2)`, stores it in
 * `rootNode_`, and recursively subdivides the area via `GenerateQuadTree`
 * starting at level 0 with maxLevel 1.
 */
void VisionDB::Init(const float width, const float height)
{
  rootNode_ = nullptr;
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits
  ForgetChainHints();   // engine addition, see gChainTails

  const Wm3::Vector2f halfSize{width * 0.5f, height * 0.5f};
  const float halfDiag = std::sqrt((halfSize.x * halfSize.x) + (halfSize.y * halfSize.y));

  // The root covers the whole area; the binary stores the doubled radius.
  const Wm3::Circle2f rootCircle{halfSize, halfDiag * 2.0f};
  Entry* const root = pool_.NewEntry(rootCircle, rootCircle, false);
  rootNode_ = root;

  GenerateQuadTree(root, halfSize, 0, 1);
}

/**
 * Address: 0x0081B080 (FUN_0081B080, Moho::VisionDB::GenerateQuadTree)
 *
 * What it does:
 * Recursively subdivides `parent` into four quadrant child nodes (NW, SW, NE,
 * SE) when `level < maxLevel`. Each child covers a half-size sub-rectangle
 * centered at the corresponding quadrant offset from the parent's stored
 * circle center, with bounding-circle radius equal to the half-diagonal of
 * the new sub-rectangle. Each new node is linked into the parent's contained
 * chain (the four inlined `AddContained`s call 0x0081A8C0 at 0x0081B146,
 * 0x0081B1CD, 0x0081B258 and 0x0081B2D6), then subdivided itself.
 */
void VisionDB::GenerateQuadTree(
  Entry* const parent,
  const Wm3::Vector2f& size,
  const int level,
  const int maxLevel)
{
  if (level >= maxLevel) {
    return;
  }

  const Wm3::Vector2f halfSize{size.x * 0.5f, size.y * 0.5f};
  const float halfDiag = std::sqrt((halfSize.x * halfSize.x) + (halfSize.y * halfSize.y));
  const float parentX = parent->mPrevCircle.Center.x;
  const float parentY = parent->mPrevCircle.Center.y;

  const auto addQuadrant = [&](const float centerX, const float centerY) {
    const Wm3::Circle2f quadrant{Wm3::Vector2f{centerX, centerY}, halfDiag};
    Entry* const child = pool_.NewEntry(quadrant, quadrant, false);
    parent->AddContained(child);
    GenerateQuadTree(child, halfSize, level + 1, maxLevel);
  };

  addQuadrant(parentX - halfSize.x, parentY - halfSize.y); // NW
  addQuadrant(parentX - halfSize.x, parentY + halfSize.y); // SW
  addQuadrant(parentX + halfSize.x, parentY - halfSize.y); // NE
  addQuadrant(parentX + halfSize.x, parentY + halfSize.y); // SE
}

/**
 * Address: 0x0081AFD0 (FUN_0081AFD0, Moho::VisionDB::NewHandle)
 *
 * What it does:
 * Takes an emitter entry from the pool for the previous/current positions
 * (radius 0 until the first `Handle::Update`), puts it in the tree from the
 * root and wraps it in a new `Handle`.
 */
VisionDB::Handle* VisionDB::NewHandle(const Wm3::Vector2f& current, const Wm3::Vector2f& previous)
{
  Entry* const entry = pool_.NewEntry(Wm3::Circle2f{previous, 0.0f}, Wm3::Circle2f{current, 0.0f}, true);

  // Engine addition (see gLastNewEntry): with no edit since the last insertion, an identical
  // entry would walk to that entry and become its first child.
  Entry* const last = gLastNewEntry.mEntry;
  if (last != nullptr && gLastNewEntry.mDb == this && gLastNewEntry.mTreeEdits == gVisionTreeEdits &&
      gLastNewEntry.mEntryEdits == gVisionEntryEdits && last->mContained == nullptr &&
      SameCircle(last->mPrevCircle, entry->mPrevCircle) && SameCircle(last->mCurCircle, entry->mCurCircle) &&
      last->Contains(*entry)) {
    last->AddContained(entry);
  } else {
    entry->PutInChain(rootNode_);
  }
  gLastNewEntry = SLastNewEntry{this, entry, gVisionTreeEdits, gVisionEntryEdits};

  return new Handle(this, entry);
}

/**
 * Address: 0x0081AEB0 (FUN_0081AEB0)
 * Address: 0x103E3E30
 *
 * What it does:
 * Clears the root pointer then tears down `Pool`.
 */
VisionDB::~VisionDB()
{
  rootNode_ = nullptr;
  NoteVisionTreeEdit(); // engine addition, see gVisionTreeEdits
  ForgetChainHints();   // engine addition: the pool's entries are about to go
}

/**
 * Address: 0x0081B490 (FUN_0081B490, Moho::VisionDB::Entry::TryAdd)
 *
 * IDA signature:
 * void __stdcall Moho::VisionDB::struct1::TryAdd(gpg::fastvector_Circle2f *accum,
 *         Moho::VisionDB::Entry *a2, const Wm3::Box3f *box, float amt);
 *
 * What it does:
 * Interpolates one vision entry's circle between its previous and current
 * samples, tests the result against the query box, and either accumulates the
 * circle (real + visible emitter) or walks the entry's contained chain.
 *
 * Field displacements taken from the shipped body:
 *   +0x04 mContained (0x0081B585), +0x08 mNext (0x0081B5A2),
 *   +0x0C mIsReal (0x0081B546),    +0x0D mVisible (0x0081B54C),
 *   +0x10/+0x14/+0x18 mPrevCircle  (0x0081B4BC/0x0081B4C1/0x0081B4ED),
 *   +0x1C/+0x20/+0x24 mCurCircle   (0x0081B4C6/0x0081B4CB/0x0081B4DC).
 *
 * The append at 0x0081B57E is the inline-backed vector's own `push_back`
 * (0x0081B6E0), so `accumulator` keeps its `fastvector_n` type; see the
 * header for what the plain base type did.
 */
void VisionDB::TryAdd(
  gpg::fastvector_n<Wm3::Circle2f, kVisibleCircleInlineCapacity>& accumulator,
  Entry* const entry,
  const Wm3::Box2f& box,
  const float interpolant
) const
{
  AccumulateVisibleCircles(accumulator, entry, box, interpolant);
}

void VisionDB::CollectVisibleCircles(
  gpg::fastvector_n<Wm3::Circle2f, kVisibleCircleInlineCapacity>& accumulator,
  const Wm3::Box2f& box,
  const float interpolant
) const
{
  if (rootNode_ == nullptr || !ren_ParallelCull || CUserWorkerPool::ConfiguredWorkerCount() == 0u) {
    TryAdd(accumulator, rootNode_, box, interpolant);
    return;
  }

  // The depth-first order `TryAdd` emits circles in is kept by expanding the walk breadth-first in
  // place: every task is replaced by its own ordered results, so concatenating the tasks' outputs
  // in task order is exactly the serial output.
  struct Task
  {
    const Entry* mSubtree; // null: `mCircle` is an already resolved circle
    Wm3::Circle2f mCircle;
  };

  // Scratch kept across frames (the fog pass runs on the main thread every frame), so the large
  // vectors do not regrow each time.
  thread_local std::vector<Task> taskScratch;
  thread_local std::vector<Task> expandedScratch;
  thread_local std::vector<std::vector<Wm3::Circle2f>> partScratch;
  // Plain references: the worker lambdas below must reach this thread's scratch, not their own.
  std::vector<Task>& tasks = taskScratch;
  std::vector<Task>& expanded = expandedScratch;
  std::vector<std::vector<Wm3::Circle2f>>& parts = partScratch;
  // The chains under the root and under its children are the long ones (the root holds the four
  // quadrant nodes, which hold most emitters); take them from the array copies.
  static VisionTopChains sTopChains;
  sTopChains.Refresh(*this, rootNode_);
  const auto forEachChild = [&](const Entry* const node, const auto& visit) {
    if (node == rootNode_) {
      for (const Entry* const child : sTopChains.mRootChain) {
        visit(child);
      }
      return;
    }
    if (node->mParent == rootNode_) {
      const auto found = std::find(sTopChains.mRootChain.begin(), sTopChains.mRootChain.end(), node);
      if (found != sTopChains.mRootChain.end()) {
        for (const Entry* const child : sTopChains.mChildChains[found - sTopChains.mRootChain.begin()]) {
          visit(child);
        }
        return;
      }
    }
    for (const Entry* child = node->mContained; child != nullptr; child = child->mNext) {
      visit(child);
    }
  };

  tasks.assign(1u, Task{rootNode_, {}});
  std::size_t subtrees = 1u;
  for (int depth = 0; depth < kVisionParallelMaxExpandDepth && subtrees != 0u && subtrees < kVisionParallelTargetSubtrees;
       ++depth) {
    expanded.clear();
    subtrees = 0u;
    for (const Task& task : tasks) {
      if (task.mSubtree == nullptr) {
        expanded.push_back(task);
        continue;
      }

      Wm3::Circle2f sampled{};
      switch (EvaluateVisionEntry(*task.mSubtree, box, interpolant, sampled)) {
        case EVisionEntryResult::Outside:
          break;
        case EVisionEntryResult::Circle:
          expanded.push_back(Task{nullptr, sampled});
          break;
        case EVisionEntryResult::Descend:
          forEachChild(task.mSubtree, [&](const Entry* const child) {
            expanded.push_back(Task{child, {}});
            ++subtrees;
          });
          break;
      }
    }
    tasks.swap(expanded);
  }

  const auto runTask = [&](auto& output, const Task& task) {
    if (task.mSubtree == nullptr) {
      output.push_back(task.mCircle);
    } else {
      AccumulateVisibleCircles(output, task.mSubtree, box, interpolant);
    }
  };

  if (subtrees < kVisionParallelMinSubtrees) {
    for (const Task& task : tasks) {
      runTask(accumulator, task);
    }
    return;
  }

  const std::size_t chunkCount = (tasks.size() + kVisionParallelGrain - 1u) / kVisionParallelGrain;
  if (parts.size() < chunkCount) {
    parts.resize(chunkCount);
  }
  CUserWorkerPool::Get().ParallelFor(tasks.size(), kVisionParallelGrain, [&](const std::size_t begin, const std::size_t end) {
    std::vector<Wm3::Circle2f>& part = parts[begin / kVisionParallelGrain];
    part.clear();
    for (std::size_t i = begin; i < end; ++i) {
      runTask(part, tasks[i]);
    }
  });

  for (std::size_t chunk = 0; chunk < chunkCount; ++chunk) {
    for (const Wm3::Circle2f& circle : parts[chunk]) {
      accumulator.push_back(circle);
    }
  }
}

void VisionDB::CollectEmitters(std::vector<EmitterCircles>& emitters) const
{
  emitters.clear();
  if (rootNode_ == nullptr) {
    return;
  }
  // `TryAdd`'s walk without the box test: an emitter ends the path, anything else is descended.
  thread_local std::vector<const Entry*> pending;
  pending.clear();
  pending.push_back(rootNode_);
  while (!pending.empty()) {
    const Entry* const entry = pending.back();
    pending.pop_back();
    if (entry->mIsReal && entry->mVisible) {
      emitters.push_back(EmitterCircles{entry->mPrevCircle, entry->mCurCircle});
      continue;
    }
    for (const Entry* child = entry->mContained; child != nullptr; child = child->mNext) {
      pending.push_back(child);
    }
  }
}

std::uint64_t VisionDB::EmitterStateVersion() noexcept
{
  return gVisionTreeEdits + gVisionEntryEdits;
}
