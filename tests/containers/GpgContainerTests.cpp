// The smaller gpg containers (src/gpg/core/containers): DList, IntrusiveLink, IntrusiveRbTree,
// Array2D, BitArray2D, Rect2, ChunkedVector, FlatGenerationMap, TrackedPointerIndex, ByteSpan.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <list>
#include <memory>
#include <random>
#include <unordered_map>
#include <vector>

#include "gpg/core/containers/Array2D.h"
#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/ByteSpan.h"
#include "gpg/core/containers/ChunkedVector.h"
#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/FlatGenerationMap.h"
#include "gpg/core/containers/IntrusiveLink.h"
#include "gpg/core/containers/IntrusiveRbTree.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/TrackedPointerIndex.h"

namespace
{
  [[nodiscard]] std::size_t Pick(std::mt19937& rng, const std::size_t maxInclusive)
  {
    return std::uniform_int_distribution<std::size_t>(0, maxInclusive)(rng);
  }

  [[nodiscard]] int PickInt(std::mt19937& rng, const int lo, const int hi)
  {
    return std::uniform_int_distribution<int>(lo, hi)(rng);
  }

  struct Item : gpg::DListItem<Item>
  {
    int value = 0;
  };

  using ItemList = gpg::DList<Item>;

  [[nodiscard]] std::vector<int> ListValues(ItemList& list)
  {
    std::vector<int> out;
    for (Item* const item : list) {
      out.push_back(item->value);
    }
    // The ring is closed both ways.
    std::vector<int> backwards;
    for (gpg::DListItem<Item>* n = list.mPrev; n != &list; n = n->mPrev) {
      backwards.push_back(n->Get()->value);
    }
    std::reverse(backwards.begin(), backwards.end());
    EXPECT_EQ(out, backwards);
    return out;
  }

  [[nodiscard]] std::vector<int> ListValues(const std::list<int>& list)
  {
    return std::vector<int>(list.begin(), list.end());
  }
} // namespace

// --- DList -------------------------------------------------------------------------------------

TEST(GpgDList, EmptyListAndUnlinkedItem)
{
  ItemList list;
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.front(), nullptr);
  EXPECT_EQ(list.back(), nullptr);
  EXPECT_EQ(list.pop_front(), nullptr);
  EXPECT_EQ(list.pop_back(), nullptr);
  EXPECT_TRUE(list.begin() == list.end());
  Item item;
  EXPECT_TRUE(item.ListIsUnlinked());
  EXPECT_FALSE(item.HasNext());
  item.ListUnlink();
  EXPECT_TRUE(item.ListIsUnlinked());
}

TEST(GpgDList, RandomOpsMatchStdList)
{
  // Items 0..31 move between two lists; each item is in at most one.
  std::mt19937 rng(1);
  std::vector<std::unique_ptr<Item>> items(32);
  for (std::size_t i = 0; i < items.size(); ++i) {
    items[i] = std::make_unique<Item>();
    items[i]->value = static_cast<int>(i);
  }
  ItemList a;
  ItemList b;
  std::list<int> refA;
  std::list<int> refB;
  const auto unlinkRef = [&](const int value) {
    refA.remove(value);
    refB.remove(value);
  };
  for (int step = 0; step < 5000; ++step) {
    const unsigned op = rng() % 12u;
    const int index = static_cast<int>(rng() % items.size());
    Item* const item = items[static_cast<std::size_t>(index)].get();
    SCOPED_TRACE(::testing::Message() << "step " << step << " op " << op << " item " << index);
    switch (op) {
    case 0:
      a.push_back(item);
      unlinkRef(index);
      refA.push_back(index);
      break;
    case 1:
      a.push_front(item);
      unlinkRef(index);
      refA.push_front(index);
      break;
    case 2:
      b.push_back(item);
      unlinkRef(index);
      refB.push_back(index);
      break;
    case 3: {
      Item* const popped = a.pop_front();
      ASSERT_EQ(popped == nullptr, refA.empty());
      if (popped != nullptr) {
        ASSERT_EQ(popped->value, refA.front());
        ASSERT_TRUE(popped->ListIsUnlinked());
        refA.pop_front();
      }
      break;
    }
    case 4: {
      Item* const popped = a.pop_back();
      ASSERT_EQ(popped == nullptr, refA.empty());
      if (popped != nullptr) {
        ASSERT_EQ(popped->value, refA.back());
        refA.pop_back();
      }
      break;
    }
    case 5:
      item->ListUnlink();
      unlinkRef(index);
      break;
    case 6:
      if (!refA.empty()) {
        // Link before / after an item that is in a.
        auto anchorIt = refA.begin();
        std::advance(anchorIt, static_cast<std::ptrdiff_t>(Pick(rng, refA.size() - 1)));
        const int anchor = *anchorIt;
        if (anchor == index) {
          break;
        }
        Item* const anchorItem = items[static_cast<std::size_t>(anchor)].get();
        const bool before = (rng() & 1u) != 0u;
        if (before) {
          item->ListLinkBefore(anchorItem);
        } else {
          item->ListLinkAfter(anchorItem);
        }
        unlinkRef(index);
        auto where = std::find(refA.begin(), refA.end(), anchor);
        if (!before) {
          ++where;
        }
        refA.insert(where, index);
      }
      break;
    case 7:
      a.splice_front(b);
      refA.splice(refA.begin(), refB);
      ASSERT_TRUE(b.empty());
      break;
    case 8: {
      ItemList pending;
      a.move_nodes_to(pending);
      ASSERT_TRUE(a.empty());
      std::list<int> refPending;
      refPending.splice(refPending.end(), refA);
      ASSERT_EQ(ListValues(pending), ListValues(refPending));
      b.splice_front(pending);
      refB.splice(refB.begin(), refPending);
      break;
    }
    case 9:
      if (rng() % 4u == 0u) {
        b.clear();
        refB.clear();
      }
      break;
    case 10: {
      // Unlink every odd item while walking: owners_safe tolerates it.
      for (Item* const owner : a.owners_safe()) {
        if ((owner->value & 1) != 0) {
          owner->ListUnlink();
        }
      }
      refA.remove_if([](const int v) { return (v & 1) != 0; });
      break;
    }
    default: {
      std::vector<int> viaOwners;
      for (Item* const owner : a.owners()) {
        viaOwners.push_back(owner->value);
      }
      ASSERT_EQ(viaOwners, ListValues(refA));
      break;
    }
    }
    ASSERT_EQ(ListValues(a), ListValues(refA));
    ASSERT_EQ(ListValues(b), ListValues(refB));
    ASSERT_EQ(a.empty(), refA.empty());
    if (!refA.empty()) {
      ASSERT_EQ(a.front()->value, refA.front());
      ASSERT_EQ(a.back()->value, refA.back());
    }
  }
  a.clear();
  b.clear();
  for (const auto& owned : items) {
    ASSERT_TRUE(owned->ListIsUnlinked());
  }
}

TEST(GpgDList, DestroyedItemsLeaveTheList)
{
  ItemList list;
  auto first = std::make_unique<Item>();
  auto second = std::make_unique<Item>();
  auto third = std::make_unique<Item>();
  first->value = 1;
  second->value = 2;
  third->value = 3;
  list.push_back(first.get());
  list.push_back(second.get());
  list.push_back(third.get());
  EXPECT_TRUE(second->HasNext());
  second.reset();
  EXPECT_EQ(ListValues(list), (std::vector<int>{1, 3}));
  const ItemList& constList = list;
  std::vector<int> viaConst;
  for (auto it = constList.begin(); it != constList.end(); ++it) {
    viaConst.push_back((*it)->value);
  }
  EXPECT_EQ(viaConst, (std::vector<int>{1, 3}));
  EXPECT_EQ(constList.front()->value, 1);
  EXPECT_EQ(constList.back()->value, 3);
}

TEST(GpgIntrusiveLink, StartsUnlinked)
{
  const gpg::core::IntrusiveLink<int*> link;
  EXPECT_EQ(link.prev, nullptr);
  EXPECT_EQ(link.next, nullptr);
}

// --- IntrusiveRbTree ---------------------------------------------------------------------------

namespace
{
  struct TreeLinks
  {
    std::uint8_t* left;
    std::uint8_t* parent;
    std::uint8_t* right;
  };

  struct TreeOwner
  {
    int key;
    TreeLinks links;
  };

  struct TreeContainer
  {
    std::uint64_t pad;
    TreeLinks head;
  };

  using OwnerTree = gpg::core::IntrusiveRbTree<
    TreeOwner,
    offsetof(TreeOwner, links),
    offsetof(TreeContainer, head),
    offsetof(TreeLinks, left),
    offsetof(TreeLinks, parent),
    offsetof(TreeLinks, right)>;

  [[nodiscard]] std::uint8_t* LinksOf(TreeOwner& owner)
  {
    return reinterpret_cast<std::uint8_t*>(&owner.links);
  }

  /** A search tree over `owners` hung from `container.head`; empty children are `nil`. */
  void BuildOwnerTree(TreeContainer& container, std::vector<TreeOwner>& owners, const bool nilIsHead)
  {
    std::uint8_t* const head = reinterpret_cast<std::uint8_t*>(&container.head);
    std::uint8_t* const nil = nilIsHead ? head : nullptr;
    container.head = TreeLinks{nullptr, nullptr, nullptr};
    TreeOwner* root = nullptr;
    TreeOwner* minimum = nullptr;
    TreeOwner* maximum = nullptr;
    for (TreeOwner& owner : owners) {
      owner.links = TreeLinks{nil, head, nil};
      if (root == nullptr) {
        root = &owner;
        minimum = &owner;
        maximum = &owner;
        continue;
      }
      TreeOwner* cur = root;
      for (;;) {
        std::uint8_t*& child = owner.key < cur->key ? cur->links.left : cur->links.right;
        if (child == nil) {
          child = LinksOf(owner);
          owner.links.parent = LinksOf(*cur);
          break;
        }
        cur = reinterpret_cast<TreeOwner*>(child - offsetof(TreeOwner, links));
      }
      if (owner.key < minimum->key) {
        minimum = &owner;
      }
      if (owner.key >= maximum->key) {
        maximum = &owner;
      }
    }
    if (root != nullptr) {
      container.head = TreeLinks{LinksOf(*minimum), LinksOf(*root), LinksOf(*maximum)};
    }
  }
} // namespace

TEST(GpgIntrusiveRbTree, WalksEmbeddedNodesInOrder)
{
  std::mt19937 rng(2);
  for (int round = 0; round < 400; ++round) {
    const bool nilIsHead = (round & 1) != 0;
    std::vector<TreeOwner> owners(Pick(rng, 30));
    std::vector<int> keys;
    for (TreeOwner& owner : owners) {
      owner.key = static_cast<int>(rng() % 50u);
      keys.push_back(owner.key);
    }
    TreeContainer container{};
    BuildOwnerTree(container, owners, nilIsHead);
    const OwnerTree tree(&container);
    EXPECT_EQ(tree.head_node(), &container.head);
    std::vector<int> walked;
    for (auto it = tree.begin(); it != tree.end(); ++it) {
      walked.push_back(it->key);
    }
    std::sort(keys.begin(), keys.end());
    ASSERT_EQ(walked, keys) << "round " << round;
    std::vector<int> postIncrement;
    for (auto it = tree.begin(); it != tree.end();) {
      postIncrement.push_back((*it++).key);
    }
    ASSERT_EQ(postIncrement, keys);
    if (owners.empty()) {
      ASSERT_EQ(tree.root_node(), nullptr);
    }
  }
}

// --- Array2D -----------------------------------------------------------------------------------

TEST(GpgArray2D, ContainsRectMatchesAScanOfTheClippedRect)
{
  std::mt19937 rng(3);
  for (int round = 0; round < 3000; ++round) {
    const int sizeX = PickInt(rng, 1, 9);
    const int sizeY = PickInt(rng, 1, 9);
    std::vector<int> cells(static_cast<std::size_t>(sizeX * sizeY));
    for (int& cell : cells) {
      const unsigned r = rng() % 12u;
      cell = r == 0u ? 1 : (r == 1u ? -1 : 0);
    }
    const gpg::Array2D grid{cells.data(), sizeX, sizeY};
    const int x = PickInt(rng, -3, sizeX + 2);
    const int z = PickInt(rng, -3, sizeY + 2);
    const int w = PickInt(rng, -2, sizeX + 3);
    const int h = PickInt(rng, -2, sizeY + 3);
    bool expected = false;
    for (int cz = 0; cz < sizeY; ++cz) {
      for (int cx = 0; cx < sizeX; ++cx) {
        if (cx >= x && cx < x + w && cz >= z && cz < z + h && cells[static_cast<std::size_t>(cz * sizeX + cx)] > 0) {
          expected = true;
        }
      }
    }
    ASSERT_EQ(grid.ContainsRect(x, z, w, h), expected)
      << "round " << round << " grid " << sizeX << "x" << sizeY << " rect " << x << "," << z << " " << w << "x" << h;
  }
}

// --- BitArray2D --------------------------------------------------------------------------------

namespace
{
  /** A plain bit grid with the same (x, z) addressing. */
  struct BitModel
  {
    int width;
    int height;
    std::vector<bool> bits;

    BitModel(const int w, const int h)
      : width(w)
      , height(h)
      , bits(static_cast<std::size_t>(w * h), false)
    {}

    [[nodiscard]] bool Get(const int x, const int z) const
    {
      return bits[static_cast<std::size_t>(z * width + x)];
    }

    void FillRect(const int x0, const int z0, const int w, const int h, const bool fill)
    {
      for (int z = std::max(z0, 0); z < std::min(z0 + h, height); ++z) {
        for (int x = std::max(x0, 0); x < std::min(x0 + w, width); ++x) {
          bits[static_cast<std::size_t>(z * width + x)] = fill;
        }
      }
    }

    [[nodiscard]] bool AnyInRect(const int x0, const int z0, const int w, const int h) const
    {
      for (int z = std::max(z0, 0); z < std::min(z0 + h, height); ++z) {
        for (int x = std::max(x0, 0); x < std::min(x0 + w, width); ++x) {
          if (Get(x, z)) {
            return true;
          }
        }
      }
      return false;
    }
  };

  [[nodiscard]] bool BitOf(const gpg::BitArray2D& array, const int x, const int z)
  {
    return array.IsBitSetOrOutOfBounds(static_cast<unsigned int>(x), static_cast<unsigned int>(z));
  }
} // namespace

TEST(GpgBitArray2D, ResetGivesAZeroedGridOfWholeWords)
{
  gpg::BitArray2D array(7u, 40u);
  EXPECT_EQ(array.width, 7);
  EXPECT_EQ(array.height, 40);
  EXPECT_EQ(array.size, 14);  // 7 columns of two 32-bit words
  for (int i = 0; i < array.size; ++i) {
    ASSERT_EQ(array.ptr[i], 0);
  }
  array.Reset(3u, 1u);
  EXPECT_EQ(array.size, 3);
  const gpg::BitArray2D empty;
  EXPECT_EQ(empty.ptr, nullptr);
  EXPECT_EQ(empty.size, 0);
}

TEST(GpgBitArray2D, RandomFillsAndQueriesMatchAPlainGrid)
{
  std::mt19937 rng(4);
  for (int round = 0; round < 60; ++round) {
    const int width = PickInt(rng, 1, 20);
    const int height = PickInt(rng, 1, 100);
    gpg::BitArray2D array(static_cast<unsigned int>(width), static_cast<unsigned int>(height));
    BitModel model(width, height);
    for (int step = 0; step < 200; ++step) {
      const int x0 = PickInt(rng, -3, width + 2);
      const int z0 = PickInt(rng, -40, height + 5);
      const int w = PickInt(rng, -2, width + 4);
      const int h = PickInt(rng, -2, height + 40);
      SCOPED_TRACE(::testing::Message() << "round " << round << " step " << step << " grid " << width << "x" << height
                                        << " rect " << x0 << "," << z0 << " " << w << "x" << h);
      switch (rng() % 5u) {
      case 0:
      case 1: {
        const bool fill = (rng() % 3u) != 0u;
        if ((rng() & 1u) != 0u) {
          array.FillRect(x0, z0, w, h, fill);
        } else {
          array.FillRect(gpg::Rect2i{x0, z0, x0 + w, z0 + h}, fill);
        }
        model.FillRect(x0, z0, w, h, fill);
        break;
      }
      case 2: {
        // Retail (0x008D8460) counts a rect that ends on the last row or column as leaving the
        // grid: x0 + w >= width, not >.
        const bool leaves = x0 < 0 || z0 < 0 || x0 + w >= width || z0 + h >= height;
        const bool nonEmpty = w > 0 && h > 0;
        ASSERT_EQ(array.GetRectOr(x0, z0, w, h, false), model.AnyInRect(x0, z0, w, h));
        ASSERT_EQ(array.GetRectOr(x0, z0, w, h, true), (leaves && nonEmpty) || model.AnyInRect(x0, z0, w, h));
        ASSERT_EQ(array.GetRectNeg(gpg::Rect2i{x0, z0, x0 + w, z0 + h}), array.GetRectOr(x0, z0, w, h, true));
        break;
      }
      case 3:
        if (x0 >= 0 && x0 < width && z0 >= 0 && z0 < height) {
          std::int32_t* const word = array.ClearBitAndReturnWord(x0, static_cast<unsigned int>(z0));
          ASSERT_EQ(word, &array.ptr[x0 + width * (z0 / 32)]);
          model.bits[static_cast<std::size_t>(z0 * width + x0)] = false;
        }
        break;
      default: {
        unsigned int foundX = 0;
        unsigned int foundZ = 0;
        unsigned int progress = static_cast<unsigned int>(rng() % static_cast<unsigned int>(array.size));
        const unsigned int start = progress;
        const bool any = array.AnyBitSet(&foundX, &foundZ, &progress);
        const bool expectedAny = model.AnyInRect(0, 0, width, height);
        ASSERT_EQ(any, expectedAny);
        if (any) {
          ASSERT_TRUE(model.Get(static_cast<int>(foundX), static_cast<int>(foundZ)));
          // The first word with a bit, scanning from `start` and wrapping.
          const unsigned int words = static_cast<unsigned int>(array.size);
          unsigned int expectedWord = start;
          while (array.ptr[expectedWord] == 0) {
            expectedWord = (expectedWord + 1u) % words;
          }
          ASSERT_EQ(progress, expectedWord);
          ASSERT_EQ(foundX, expectedWord % static_cast<unsigned int>(width));
        }
        break;
      }
      }
      std::vector<bool> got(model.bits.size());
      for (int z = 0; z < height; ++z) {
        for (int x = 0; x < width; ++x) {
          got[static_cast<std::size_t>(z * width + x)] = BitOf(array, x, z);
        }
      }
      ASSERT_EQ(got, model.bits);
      ASSERT_TRUE(array.IsBitSetOrOutOfBounds(static_cast<unsigned int>(width), 0u));
      ASSERT_TRUE(array.IsBitSetOrOutOfBounds(0u, static_cast<unsigned int>(height)));
    }
    const gpg::BitArray2D copy(array);
    ASSERT_EQ(copy.size, array.size);
    for (int i = 0; i < array.size; ++i) {
      ASSERT_EQ(copy.ptr[i], array.ptr[i]);
    }
  }
}

TEST(GpgBitArray2D, AnyBitSetOnAnEmptyGrid)
{
  gpg::BitArray2D array(4u, 4u);
  unsigned int x = 99;
  unsigned int z = 99;
  EXPECT_FALSE(array.AnyBitSet(&x, &z, nullptr));
  EXPECT_FALSE(array.AnyBitSet(nullptr, &z, nullptr));
  array.FillRect(2, 3, 1, 1, true);
  EXPECT_TRUE(array.AnyBitSet(&x, &z, nullptr));
  EXPECT_EQ(x, 2u);
  EXPECT_EQ(z, 3u);
  (void)gpg::DestroyAndDeleteBitArray2D(new gpg::BitArray2D(5u, 5u));
}

// --- Rect2 -------------------------------------------------------------------------------------

TEST(GpgRect2, PredicatesMatchCellCounts)
{
  std::mt19937 rng(5);
  for (int round = 0; round < 20000; ++round) {
    const gpg::Rect2i a{PickInt(rng, 0, 6), PickInt(rng, 0, 6), PickInt(rng, 0, 6), PickInt(rng, 0, 6)};
    const gpg::Rect2i b{PickInt(rng, 0, 6), PickInt(rng, 0, 6), PickInt(rng, 0, 6), PickInt(rng, 0, 6)};
    SCOPED_TRACE(::testing::Message() << "round " << round);
    // IsRegular is true for an empty rect (the binary's name).
    ASSERT_EQ(a.IsRegular(), a.x0 >= a.x1 || a.z0 >= a.z1);
    bool shareCell = false;
    bool shareClosedPoint = false;
    for (int z = 0; z <= 6; ++z) {
      for (int x = 0; x <= 6; ++x) {
        ASSERT_EQ(a.Contains(x, z), x >= a.x0 && x < a.x1 && z >= a.z0 && z < a.z1);
        if (a.Contains(x, z) && b.Contains(x, z)) {
          shareCell = true;
        }
        const bool inA = x >= a.x0 && x <= a.x1 && z >= a.z0 && z <= a.z1;
        const bool inB = x >= b.x0 && x <= b.x1 && z >= b.z0 && z <= b.z1;
        if (inA && inB) {
          shareClosedPoint = true;
        }
      }
    }
    const bool bothNonEmpty = !a.IsRegular() && !b.IsRegular();
    ASSERT_EQ(a.Overlaps(b), shareCell);
    ASSERT_EQ(a.OverlapsInclusive(b), bothNonEmpty && shareClosedPoint);
    ASSERT_EQ(a.Overlaps(b), b.Overlaps(a));
    if (bothNonEmpty && !a.Overlaps(b)) {
      ASSERT_EQ(a.Touches(b), shareClosedPoint);
    }
    gpg::Rect2i clipped = a;
    clipped.IntersectWith(b);
    ASSERT_EQ(clipped.x0, std::max(a.x0, b.x0));
    ASSERT_EQ(clipped.z0, std::max(a.z0, b.z0));
    ASSERT_EQ(clipped.x1, std::min(a.x1, b.x1));
    ASSERT_EQ(clipped.z1, std::min(a.z1, b.z1));
  }
}

TEST(GpgRect2, FloatRect)
{
  const gpg::Rect2f a{0.0f, 0.0f, 1.0f, 1.0f};
  const gpg::Rect2f b{0.5f, 0.5f, 2.0f, 2.0f};
  const gpg::Rect2f c{1.0f, 0.0f, 2.0f, 1.0f};
  EXPECT_TRUE(a.Contains(0.0f, 0.999f));
  EXPECT_FALSE(a.Contains(1.0f, 0.5f));
  EXPECT_TRUE(a.Overlaps(b));
  EXPECT_FALSE(a.Overlaps(c));
  EXPECT_TRUE(a.OverlapsInclusive(c));
  EXPECT_TRUE(a.Touches(c));
  EXPECT_FALSE(gpg::Rect2f{}.Touches(a));
}

// --- ChunkedVector -----------------------------------------------------------------------------

TEST(GpgChunkedVector, PushAcrossChunksAndKeepAddresses)
{
  gpg::core::ChunkedVector<int, 2> v;  // chunks of 4
  EXPECT_EQ(v.size(), 0u);
  std::vector<int*> addresses;
  for (int i = 0; i < 1000; ++i) {
    int& element = v.push_back(i);
    ASSERT_EQ(element, i);
    addresses.push_back(&element);
  }
  EXPECT_EQ(v.size(), 1000u);
  for (std::size_t i = 0; i < 1000; ++i) {
    ASSERT_EQ(v[i], static_cast<int>(i));
    ASSERT_EQ(&v[i], addresses[i]);
  }
  const auto& constView = v;
  EXPECT_EQ(constView[999], 999);

  v.clear();
  EXPECT_EQ(v.size(), 0u);
  v.push_back(-1);
  EXPECT_EQ(&v[0], addresses[0]);
  EXPECT_EQ(v[0], -1);

  v.grow_to(10);
  EXPECT_EQ(v.size(), 10u);
  v.grow_to(5);
  EXPECT_EQ(v.size(), 10u);
  EXPECT_EQ(gpg::core::ChunkedVector<int>::kChunkSize, 256u);
}

// --- FlatGenerationMap -------------------------------------------------------------------------

namespace
{
  void RunFlatMapRandomOps(const unsigned seed, const unsigned capacityLog2, const std::uint32_t keyRange)
  {
    std::mt19937 rng(seed);
    gpg::core::FlatGenerationMap<int> map(capacityLog2);
    std::unordered_map<std::uint32_t, int> ref;
    for (int step = 0; step < 4000; ++step) {
      const std::uint32_t key = static_cast<std::uint32_t>(rng() % keyRange) * 2654435761u;
      const int value = static_cast<int>(rng() % 1000u);
      const unsigned op = rng() % 10u;
      SCOPED_TRACE(::testing::Message() << "seed " << seed << " step " << step << " op " << op << " key " << key);
      if (op < 5) {
        if (ref.count(key) == 0) {
          int& stored = map.Insert(key, value);
          ASSERT_EQ(stored, value);
          ref[key] = value;
        }
      } else if (op < 8) {
        map.Erase(key);
        ref.erase(key);
      } else if (op == 8) {
        int* const found = map.Find(key);
        if (found != nullptr) {
          *found += 1;
          ref[key] += 1;
        }
      } else if (rng() % 20u == 0u) {
        map.Clear();
        ref.clear();
      }
      if (ref.size() < 200 || step % 16 == 0) {
        for (const auto& [k, v] : ref) {
          const int* const found = map.Find(k);
          ASSERT_NE(found, nullptr) << k;
          ASSERT_EQ(*found, v) << k;
        }
      }
      for (int probe = 0; probe < 4; ++probe) {
        const std::uint32_t absent = static_cast<std::uint32_t>(rng() % keyRange) * 2654435761u;
        if (ref.count(absent) == 0) {
          ASSERT_EQ(map.Find(absent), nullptr) << absent;
        }
      }
    }
  }
} // namespace

TEST(GpgFlatGenerationMap, RandomOpsMatchUnorderedMap)
{
  RunFlatMapRandomOps(1, 1, 64);
  RunFlatMapRandomOps(2, 2, 300);
  RunFlatMapRandomOps(3, 10, 3000);
  RunFlatMapRandomOps(4, 3, 20);
}

TEST(GpgFlatGenerationMap, ClearForgetsEveryKeyAtOnce)
{
  gpg::core::FlatGenerationMap<int> map(4);
  for (std::uint32_t round = 0; round < 50; ++round) {
    for (std::uint32_t i = 0; i < 100; ++i) {
      map.Insert(i + round * 1000u, static_cast<int>(i));
    }
    for (std::uint32_t i = 0; i < 100; ++i) {
      ASSERT_NE(map.Find(i + round * 1000u), nullptr);
    }
    map.Clear();
    for (std::uint32_t i = 0; i < 100; ++i) {
      ASSERT_EQ(map.Find(i + round * 1000u), nullptr);
    }
  }
  map.Erase(12345u);
  EXPECT_EQ(map.Find(12345u), nullptr);
}

// --- TrackedPointerIndex -----------------------------------------------------------------------

TEST(GpgTrackedPointerIndex, FindsEveryInsertedKeyAcrossGrowth)
{
  // 40000 entries: past one chunk of 16384 and past the first growth at 32768.
  auto index = std::make_unique<gpg::TrackedPointerIndex>();
  constexpr std::uint32_t kCount = 40000u;
  const auto objectOf = [](const std::uint32_t i) {
    return reinterpret_cast<void*>(static_cast<std::uintptr_t>(0x10000u + 16u * i));
  };
  const auto typeOf = [](const std::uint32_t i) {
    return reinterpret_cast<gpg::RType*>(static_cast<std::uintptr_t>(0x1000u + 64u * (i % 7u)));
  };
  for (std::uint32_t i = 0; i < kCount; ++i) {
    gpg::WriteArchive::TrackedPointerRecord record{};
    record.index = static_cast<int>(i);
    gpg::TrackedPointerIndex::Entry& entry = index->Insert(gpg::RRef{objectOf(i), typeOf(i)}, record);
    ASSERT_EQ(entry.record.index, static_cast<int>(i));
  }
  EXPECT_EQ(index->Size(), kCount);
  for (std::uint32_t i = 0; i < kCount; ++i) {
    gpg::TrackedPointerIndex::Entry* const found = index->Find(gpg::RRef{objectOf(i), typeOf(i)});
    ASSERT_NE(found, nullptr) << i;
    ASSERT_EQ(found->record.index, static_cast<int>(i));
    ASSERT_EQ(found, &index->At(i));
    // The same object under another type is another key.
    ASSERT_EQ(index->Find(gpg::RRef{objectOf(i), typeOf(i + 1u)}), nullptr) << i;
  }
  EXPECT_EQ(index->Find(gpg::RRef{objectOf(kCount), typeOf(kCount)}), nullptr);

  index->Clear();
  EXPECT_EQ(index->Size(), 0u);
  EXPECT_EQ(index->Find(gpg::RRef{objectOf(1), typeOf(1)}), nullptr);
  gpg::WriteArchive::TrackedPointerRecord record{};
  record.index = 77;
  index->Insert(gpg::RRef{objectOf(1), typeOf(1)}, record);
  ASSERT_NE(index->Find(gpg::RRef{objectOf(1), typeOf(1)}), nullptr);
  EXPECT_EQ(index->Find(gpg::RRef{objectOf(1), typeOf(1)})->record.index, 77);
}

TEST(GpgByteSpan, SizeIsTheDistance)
{
  const char text[] = "abcdef";
  const gpg::ByteSpan span{text + 1, text + 4};
  EXPECT_EQ(span.size(), 3u);
  EXPECT_EQ(gpg::ByteSpan{}.size(), 0u);
}
