#include "moho/render/d3d/CD3DEffectTechnique.h"

#include <cstring>
#include <cstdlib>
#include <exception>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectTechniqueD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/ID3DTextureSheet.h"

namespace moho
{
  msvc8::string GetEngineVersion();

  namespace
  {
    using Implementation = CD3DEffect::Technique::Implementation;
    using IntAnnotationNode = Implementation::IntAnnotationNode;
    using StringAnnotationNode = Implementation::StringAnnotationNode;
    using IntAnnotationTree = Implementation::IntAnnotationTree;
    using StringAnnotationTree = Implementation::StringAnnotationTree;
    using TechniqueNode = CD3DEffect::TechniqueNode;
    using TechniqueTree = CD3DEffect::TechniqueTree;

    template <typename T>
    struct PointerFlagPair
    {
      T* pointer;               // +0x00
      std::uint8_t boolTag;     // +0x04
    };

    static_assert(sizeof(PointerFlagPair<void>) == 0x08, "PointerFlagPair size must be 0x08");

    [[nodiscard]] int CompareStringViews(const std::string_view lhs, const std::string_view rhs) noexcept
    {
      const std::size_t commonCount = (lhs.size() < rhs.size()) ? lhs.size() : rhs.size();
      const int prefixCompare = std::char_traits<char>::compare(lhs.data(), rhs.data(), commonCount);
      if (prefixCompare != 0) {
        return prefixCompare;
      }

      if (lhs.size() < rhs.size()) {
        return -1;
      }
      if (lhs.size() > rhs.size()) {
        return 1;
      }
      return 0;
    }

    [[nodiscard]] int CompareLegacyStrings(const msvc8::string& lhs, const msvc8::string& rhs) noexcept
    {
      return CompareStringViews(lhs.view(), rhs.view());
    }

    [[nodiscard]] IntAnnotationNode* AllocateIntAnnotationSentinel()
    {
      void* const storage = ::operator new(sizeof(IntAnnotationNode));
      auto* const head = static_cast<IntAnnotationNode*>(storage);
      head->mLeft = nullptr;
      head->mParent = nullptr;
      head->mRight = nullptr;
      head->mColor = 1;
      head->mIsNil = 0;
      return head;
    }

    [[nodiscard]] StringAnnotationNode* AllocateStringAnnotationSentinel()
    {
      void* const storage = ::operator new(sizeof(StringAnnotationNode));
      auto* const head = static_cast<StringAnnotationNode*>(storage);
      head->mLeft = nullptr;
      head->mParent = nullptr;
      head->mRight = nullptr;
      head->mColor = 1;
      head->mIsNil = 0;
      return head;
    }

    template <typename NodeT>
    void InitializeSentinelMap(
      Implementation::AnnotationTreeMap<NodeT>& map,
      NodeT* const head
    ) noexcept
    {
      map.mHead = head;
      head->mIsNil = 1;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      map.mSize = 0;
    }

    /**
     * Address: 0x00432400 (FUN_00432400)
     *
     * What it does:
     * Initializes one integer-annotation tree lane with a fresh sentinel node.
     */
    IntAnnotationTree* InitializeIntAnnotationTreeStorage(IntAnnotationTree* const outTree)
    {
      if (outTree == nullptr) {
        return nullptr;
      }

      IntAnnotationNode* const head = AllocateIntAnnotationSentinel();
      InitializeSentinelMap(*outTree, head);
      return outTree;
    }

    /**
     * Address: 0x00432430 (FUN_00432430)
     *
     * What it does:
     * Returns the current begin-node pointer for one integer-annotation tree.
     */
    [[nodiscard]] IntAnnotationNode* GetIntAnnotationTreeBegin(const IntAnnotationTree& tree) noexcept
    {
      IntAnnotationNode* const head = tree.mHead;
      return head != nullptr ? head->mLeft : nullptr;
    }

    /**
     * Address: 0x00432440 (FUN_00432440)
     *
     * What it does:
     * Returns the sentinel-head pointer for one integer-annotation tree.
     */
    [[nodiscard]] IntAnnotationNode* GetIntAnnotationTreeHead(const IntAnnotationTree& tree) noexcept
    {
      return tree.mHead;
    }

    void DestroyIntegerTreeNodes(IntAnnotationNode* node) noexcept
    {
      IntAnnotationNode* current = node;
      while (current != nullptr && current->mIsNil == 0u) {
        DestroyIntegerTreeNodes(current->mRight);

        IntAnnotationNode* const next = current->mLeft;
        current->mKey.tidy(true, 0U);
        ::operator delete(current);
        current = next;
      }
    }

    void DestroyStringTreeNodes(StringAnnotationNode* node) noexcept
    {
      StringAnnotationNode* current = node;
      while (current != nullptr && current->mIsNil == 0u) {
        DestroyStringTreeNodes(current->mRight);

        StringAnnotationNode* const next = current->mLeft;
        current->mValue.tidy(true, 0U);
        current->mKey.tidy(true, 0U);
        ::operator delete(current);
        current = next;
      }
    }

    template <typename NodeT>
    void DestroyAnnotationMap(
      Implementation::AnnotationTreeMap<NodeT>& map,
      void (*destroyNodes)(NodeT*) noexcept
    ) noexcept
    {
      NodeT* const head = map.mHead;
      destroyNodes(head->mParent);
      ::operator delete(head);
      map.mHead = nullptr;
      map.mSize = 0;
    }

    template <typename NodeT>
    void ClearAnnotationMapNodes(
      Implementation::AnnotationTreeMap<NodeT>& map,
      void (*destroyNodes)(NodeT*) noexcept
    ) noexcept
    {
      NodeT* const head = map.mHead;
      destroyNodes(head->mParent);
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      map.mSize = 0;
    }

    /**
     * Address: 0x004325C0 (FUN_004325C0)
     *
     * What it does:
     * Erases integer-annotation tree content for the full-range erase case used
     * by implementation teardown/assignment paths.
     */
    void ClearIntAnnotationTreeFullRange(IntAnnotationTree& tree) noexcept
    {
      IntAnnotationNode* const begin = GetIntAnnotationTreeBegin(tree);
      IntAnnotationNode* const head = GetIntAnnotationTreeHead(tree);
      if (begin == nullptr || head == nullptr || begin == head) {
        tree.mSize = 0;
        return;
      }

      ClearAnnotationMapNodes(tree, &DestroyIntegerTreeNodes);
    }

    template <typename NodeT>
    [[nodiscard]] NodeT* FindTreeMinNode(NodeT* node) noexcept
    {
      NodeT* current = node;
      while (current != nullptr && current->mLeft != nullptr && current->mLeft->mIsNil == 0u) {
        current = current->mLeft;
      }
      return current;
    }

    template <typename NodeT>
    [[nodiscard]] NodeT* FindTreeMaxNode(NodeT* node) noexcept
    {
      NodeT* current = node;
      while (current != nullptr && current->mRight != nullptr && current->mRight->mIsNil == 0u) {
        current = current->mRight;
      }
      return current;
    }

    template <typename NodeT>
    void RefreshHeadBounds(Implementation::AnnotationTreeMap<NodeT>& map) noexcept
    {
      NodeT* const head = map.mHead;
      if (head->mParent->mIsNil != 0u) {
        head->mParent = head;
        head->mLeft = head;
        head->mRight = head;
        return;
      }

      head->mLeft = FindTreeMinNode(head->mParent);
      head->mRight = FindTreeMaxNode(head->mParent);
    }

    [[nodiscard]] IntAnnotationNode* CloneIntegerSubtree(
      const IntAnnotationNode* const sourceNode,
      const IntAnnotationNode* const sourceHead,
      IntAnnotationNode* const destinationHead,
      IntAnnotationNode* const parentNode
    )
    {
      if (sourceNode == nullptr || sourceNode == sourceHead || sourceNode->mIsNil != 0u) {
        return destinationHead;
      }

      auto* const clonedNode = new IntAnnotationNode();
      clonedNode->mParent = parentNode;
      clonedNode->mKey.assign(sourceNode->mKey, 0U, msvc8::string::npos);
      clonedNode->mValue = sourceNode->mValue;
      clonedNode->mColor = sourceNode->mColor;
      clonedNode->mIsNil = 0;
      clonedNode->mPad2E[0] = sourceNode->mPad2E[0];
      clonedNode->mPad2E[1] = sourceNode->mPad2E[1];
      clonedNode->mLeft = CloneIntegerSubtree(sourceNode->mLeft, sourceHead, destinationHead, clonedNode);
      clonedNode->mRight = CloneIntegerSubtree(sourceNode->mRight, sourceHead, destinationHead, clonedNode);
      return clonedNode;
    }

    [[nodiscard]] StringAnnotationNode* CloneStringSubtree(
      const StringAnnotationNode* const sourceNode,
      const StringAnnotationNode* const sourceHead,
      StringAnnotationNode* const destinationHead,
      StringAnnotationNode* const parentNode
    )
    {
      if (sourceNode == nullptr || sourceNode == sourceHead || sourceNode->mIsNil != 0u) {
        return destinationHead;
      }

      auto* const clonedNode = new StringAnnotationNode();
      clonedNode->mParent = parentNode;
      clonedNode->mKey.assign(sourceNode->mKey, 0U, msvc8::string::npos);
      clonedNode->mValue.assign(sourceNode->mValue, 0U, msvc8::string::npos);
      clonedNode->mColor = sourceNode->mColor;
      clonedNode->mIsNil = 0;
      clonedNode->mPad46[0] = sourceNode->mPad46[0];
      clonedNode->mPad46[1] = sourceNode->mPad46[1];
      clonedNode->mLeft = CloneStringSubtree(sourceNode->mLeft, sourceHead, destinationHead, clonedNode);
      clonedNode->mRight = CloneStringSubtree(sourceNode->mRight, sourceHead, destinationHead, clonedNode);
      return clonedNode;
    }

    void CopyIntegerAnnotationTree(IntAnnotationTree& destination, const IntAnnotationTree& source)
    {
      IntAnnotationNode* const destinationHead = destination.mHead;
      const IntAnnotationNode* const sourceHead = source.mHead;
      destinationHead->mParent = CloneIntegerSubtree(sourceHead->mParent, sourceHead, destinationHead, destinationHead);
      destination.mSize = source.mSize;
      RefreshHeadBounds(destination);
    }

    void CopyStringAnnotationTree(StringAnnotationTree& destination, const StringAnnotationTree& source)
    {
      StringAnnotationNode* const destinationHead = destination.mHead;
      const StringAnnotationNode* const sourceHead = source.mHead;
      destinationHead->mParent = CloneStringSubtree(sourceHead->mParent, sourceHead, destinationHead, destinationHead);
      destination.mSize = source.mSize;
      RefreshHeadBounds(destination);
    }

    /**
     * Address: 0x0042C150 (FUN_0042C150)
     *
     * What it does:
     * Destroys the integer-annotation tree storage and clears the tree header lane.
     */
    int DestroyIntegerAnnotationTreeStorage(IntAnnotationTree& tree) noexcept
    {
      DestroyAnnotationMap(tree, &DestroyIntegerTreeNodes);
      return 0;
    }

    /**
     * Address: 0x0042C180 (FUN_0042C180)
     *
     * What it does:
     * Destroys the string-annotation tree storage and clears the tree header lane.
     */
    int DestroyStringAnnotationTreeStorage(StringAnnotationTree& tree) noexcept
    {
      DestroyAnnotationMap(tree, &DestroyStringTreeNodes);
      return 0;
    }

    /**
     * Address: 0x0042C2C0 (FUN_0042C2C0)
     * Address: 0x00432690 (FUN_00432690, shared tree-assign helper lane)
     *
     * What it does:
     * Replaces one integer-annotation tree with a copy of another tree lane.
     */
    IntAnnotationTree& AssignIntegerAnnotationTree(IntAnnotationTree& destination, const IntAnnotationTree& source)
    {
      if (&destination != &source) {
        ClearIntAnnotationTreeFullRange(destination);
        CopyIntegerAnnotationTree(destination, source);
      }
      return destination;
    }

    /**
     * Address: 0x0042C2F0 (FUN_0042C2F0)
     *
     * What it does:
     * Replaces one string-annotation tree with a copy of another tree lane.
     */
    StringAnnotationTree& AssignStringAnnotationTree(StringAnnotationTree& destination, const StringAnnotationTree& source)
    {
      if (&destination != &source) {
        ClearAnnotationMapNodes(destination, &DestroyStringTreeNodes);
        CopyStringAnnotationTree(destination, source);
      }
      return destination;
    }

    [[nodiscard]] bool HasConstructedLaneName(const Implementation& lane) noexcept
    {
      return lane.mName.myRes != 0U;
    }

    template <typename NodeT>
    [[nodiscard]] NodeT* LowerBoundAnnotationNode(
      const Implementation::AnnotationTreeMap<NodeT>& map,
      const msvc8::string& key
    ) noexcept
    {
      NodeT* const head = map.mHead;
      NodeT* result = head;
      NodeT* node = head->mParent;
      while (node != nullptr && node->mIsNil == 0u) {
        if (CompareLegacyStrings(node->mKey, key) >= 0) {
          result = node;
          node = node->mLeft;
        } else {
          node = node->mRight;
        }
      }

      return result;
    }

    /**
     * Address: 0x00432450 (FUN_00432450)
     *
     * What it does:
     * Returns the lower-bound node for one integer-annotation key query.
     */
    [[nodiscard]] IntAnnotationNode*
    LowerBoundIntAnnotationNode(const IntAnnotationTree& tree, const msvc8::string& key) noexcept
    {
      return LowerBoundAnnotationNode(tree, key);
    }

    template <typename NodeT>
    [[nodiscard]] NodeT* FindAnnotationNode(
      const Implementation::AnnotationTreeMap<NodeT>& map,
      const msvc8::string& key
    ) noexcept
    {
      NodeT* const head = map.mHead;
      NodeT* const lowerBound = LowerBoundAnnotationNode(map, key);
      if (lowerBound == nullptr || lowerBound == head || CompareLegacyStrings(key, lowerBound->mKey) < 0) {
        return head;
      }

      return lowerBound;
    }

    /**
     * Address: 0x00432680 (FUN_00432680)
     *
     * What it does:
     * Returns one integer-annotation node matching the requested key (or
     * sentinel when absent).
     */
    [[nodiscard]] IntAnnotationNode*
    FindIntAnnotationNodeBridge(const IntAnnotationTree& tree, const msvc8::string& key) noexcept
    {
      IntAnnotationNode* const head = GetIntAnnotationTreeHead(tree);
      IntAnnotationNode* const lowerBound = LowerBoundIntAnnotationNode(tree, key);
      if (lowerBound == nullptr || lowerBound == head || CompareLegacyStrings(key, lowerBound->mKey) < 0) {
        return head;
      }

      return lowerBound;
    }

    template <typename T>
    [[nodiscard]] boost::shared_ptr<T>& SharedHandleAsBoost(CD3DEffect::SharedHandle<T>& handle) noexcept
    {
      static_assert(
        sizeof(CD3DEffect::SharedHandle<T>) == sizeof(boost::shared_ptr<T>),
        "CD3DEffect::SharedHandle<T> layout must match boost::shared_ptr<T>"
      );
      return *reinterpret_cast<boost::shared_ptr<T>*>(&handle);
    }

    template <typename T>
    [[nodiscard]] const boost::shared_ptr<T>& SharedHandleAsBoost(
      const CD3DEffect::SharedHandle<T>& handle
    ) noexcept
    {
      static_assert(
        sizeof(CD3DEffect::SharedHandle<T>) == sizeof(boost::shared_ptr<T>),
        "CD3DEffect::SharedHandle<T> layout must match boost::shared_ptr<T>"
      );
      return *reinterpret_cast<const boost::shared_ptr<T>*>(&handle);
    }

    /**
     * Address: 0x0042C320 (FUN_0042C320)
     *
     * What it does:
     * Writes one `{pointer, bool-tag}` pair and returns the output lane.
     */
    template <typename T>
    [[nodiscard]] PointerFlagPair<T>* InitializePointerFlagPair(
      PointerFlagPair<T>* const outPair,
      const bool boolTag,
      T* const pointer
    ) noexcept
    {
      outPair->pointer = pointer;
      outPair->boolTag = static_cast<std::uint8_t>(boolTag ? 1u : 0u);
      return outPair;
    }

    /**
     * Address family:
     * - 0x0042C240 (FUN_0042C240)
     * - 0x0042C280 (FUN_0042C280)
     * - 0x0042C330 (FUN_0042C330)
     * - 0x0042C370 (FUN_0042C370)
     * - 0x0042C4E0 (FUN_0042C4E0)
     *
     * What it does:
     * Releases one shared-handle lane and clears ownership.
     */
    template <typename T>
    int ReleaseSharedHandle(CD3DEffect::SharedHandle<T>* const handle) noexcept
    {
      SharedHandleAsBoost(*handle).reset();
      return 0;
    }

    [[nodiscard]] TechniqueNode* AllocateTechniqueSentinel()
    {
      void* const storage = ::operator new(sizeof(TechniqueNode));
      auto* const head = static_cast<TechniqueNode*>(storage);
      head->mLeft = nullptr;
      head->mParent = nullptr;
      head->mRight = nullptr;
      head->mColor = 1;
      head->mIsNil = 0;
      return head;
    }

    void InitializeTechniqueTree(TechniqueTree& tree, TechniqueNode* const head) noexcept
    {
      tree.mHead = head;
      head->mIsNil = 1;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      tree.mSize = 0;
    }

    void DestroyTechniqueTreeNodes(TechniqueNode* node) noexcept
    {
      TechniqueNode* current = node;
      while (current != nullptr && current->mIsNil == 0u) {
        DestroyTechniqueTreeNodes(current->mRight);
        TechniqueNode* const next = current->mLeft;
        current->mTechnique.~Technique();
        ::operator delete(current);
        current = next;
      }
    }

    /**
     * Address: 0x0042C4B0 (FUN_0042C4B0)
     *
     * What it does:
     * Destroys one effect technique-definition tree and clears tree header storage.
     */
    int DestroyTechniqueTreeStorage(TechniqueTree& tree) noexcept
    {
      TechniqueNode* const head = tree.mHead;
      if (head != nullptr) {
        PointerFlagPair<TechniqueNode> beginCursor{};
        (void)InitializePointerFlagPair(&beginCursor, false, head->mLeft);
        DestroyTechniqueTreeNodes(head->mParent);
        ::operator delete(head);
      }

      tree.mHead = nullptr;
      tree.mSize = 0;
      return 0;
    }

    [[nodiscard]] TechniqueNode* LowerBoundTechniqueNode(
      const TechniqueTree& tree,
      const msvc8::string& techniqueName
    ) noexcept
    {
      TechniqueNode* const head = tree.mHead;
      TechniqueNode* result = head;
      TechniqueNode* node = head->mParent;
      while (node != nullptr && node->mIsNil == 0u) {
        if (CompareLegacyStrings(node->mTechnique.mName, techniqueName) >= 0) {
          result = node;
          node = node->mLeft;
        } else {
          node = node->mRight;
        }
      }
      return result;
    }

    [[nodiscard]] TechniqueNode* FindTechniqueNode(
      const TechniqueTree& tree,
      const msvc8::string& techniqueName
    ) noexcept
    {
      TechniqueNode* const head = tree.mHead;
      TechniqueNode* const lowerBound = LowerBoundTechniqueNode(tree, techniqueName);
      if (lowerBound == nullptr || lowerBound == head || CompareLegacyStrings(techniqueName, lowerBound->mTechnique.mName) < 0) {
        return head;
      }
      return lowerBound;
    }

    /**
     * Address: 0x00432B10 (FUN_00432B10)
     *
     * What it does:
     * Destroys all non-sentinel fidelity-definition nodes and restores the tree
     * to the empty sentinel-only state.
     */
    void ClearTechniqueTreeNodes(TechniqueTree& tree) noexcept
    {
      TechniqueNode* const head = tree.mHead;
      if (head == nullptr) {
        return;
      }

      DestroyTechniqueTreeNodes(head->mParent);
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      tree.mSize = 0;
    }

    constexpr std::uint8_t kTreeColorRed = 0;
    constexpr std::uint8_t kTreeColorBlack = 1;
    constexpr std::uint32_t kMaxTechniqueTreeNodeCount = 0x0147AE12;
    constexpr std::uint32_t kMaxAnnotationTreeNodeCount = 0x07FFFFFD;

    [[noreturn]] void ThrowMapSetTooLong()
    {
      throw std::length_error("map/set<T> too long");
    }

    /**
     * Address family:
     * - 0x004345A0 (FUN_004345A0)
     * - 0x00434CA0 (FUN_00434CA0)
     *
     * What it does:
     * Performs one left rotation around the provided tree node.
     */
    template <typename TreeT, typename NodeT>
    void RotateTreeLeft(TreeT& tree, NodeT* const pivot) noexcept
    {
      NodeT* const head = tree.mHead;
      NodeT* const right = pivot->mRight;
      pivot->mRight = right->mLeft;
      if (right->mLeft->mIsNil == 0u) {
        right->mLeft->mParent = pivot;
      }

      right->mParent = pivot->mParent;
      if (pivot == head->mParent) {
        head->mParent = right;
      } else if (pivot == pivot->mParent->mLeft) {
        pivot->mParent->mLeft = right;
      } else {
        pivot->mParent->mRight = right;
      }

      right->mLeft = pivot;
      pivot->mParent = right;
    }

    /**
     * Address family:
     * - 0x00434550 (FUN_00434550)
     * - 0x00434C50 (FUN_00434C50)
     *
     * What it does:
     * Performs one right rotation around the provided tree node.
     */
    template <typename TreeT, typename NodeT>
    void RotateTreeRight(TreeT& tree, NodeT* const pivot) noexcept
    {
      NodeT* const head = tree.mHead;
      NodeT* const left = pivot->mLeft;
      pivot->mLeft = left->mRight;
      if (left->mRight->mIsNil == 0u) {
        left->mRight->mParent = pivot;
      }

      left->mParent = pivot->mParent;
      if (pivot == head->mParent) {
        head->mParent = left;
      } else if (pivot == pivot->mParent->mRight) {
        pivot->mParent->mRight = left;
      } else {
        pivot->mParent->mLeft = left;
      }

      left->mRight = pivot;
      pivot->mParent = left;
    }

    /**
     * Address family:
     * - 0x00432B60 (FUN_00432B60)
     * - 0x00433900 (FUN_00433900)
     *
     * What it does:
     * Restores red-black invariants after linking one freshly allocated node.
     */
    template <typename TreeT, typename NodeT>
    void RebalanceTreeAfterInsert(TreeT& tree, NodeT* inserted) noexcept
    {
      NodeT* node = inserted;
      while (node->mParent->mColor == kTreeColorRed) {
        if (node->mParent == node->mParent->mParent->mLeft) {
          NodeT* const uncle = node->mParent->mParent->mRight;
          if (uncle->mColor == kTreeColorRed) {
            node->mParent->mColor = kTreeColorBlack;
            uncle->mColor = kTreeColorBlack;
            node->mParent->mParent->mColor = kTreeColorRed;
            node = node->mParent->mParent;
          } else {
            if (node == node->mParent->mRight) {
              node = node->mParent;
              RotateTreeLeft(tree, node);
            }
            node->mParent->mColor = kTreeColorBlack;
            node->mParent->mParent->mColor = kTreeColorRed;
            RotateTreeRight(tree, node->mParent->mParent);
          }
        } else {
          NodeT* const uncle = node->mParent->mParent->mLeft;
          if (uncle->mColor == kTreeColorRed) {
            node->mParent->mColor = kTreeColorBlack;
            uncle->mColor = kTreeColorBlack;
            node->mParent->mParent->mColor = kTreeColorRed;
            node = node->mParent->mParent;
          } else {
            if (node == node->mParent->mLeft) {
              node = node->mParent;
              RotateTreeRight(tree, node);
            }
            node->mParent->mColor = kTreeColorBlack;
            node->mParent->mParent->mColor = kTreeColorRed;
            RotateTreeLeft(tree, node->mParent->mParent);
          }
        }
      }

      tree.mHead->mParent->mColor = kTreeColorBlack;
    }

    template <typename TreeT, typename NodeT>
    void LinkInsertedTreeNode(TreeT& tree, NodeT* const parent, NodeT* const inserted, const bool insertLeft) noexcept
    {
      NodeT* const head = tree.mHead;
      if (parent == head) {
        head->mParent = inserted;
        head->mLeft = inserted;
        head->mRight = inserted;
      } else if (insertLeft) {
        parent->mLeft = inserted;
        if (parent == head->mLeft) {
          head->mLeft = inserted;
        }
      } else {
        parent->mRight = inserted;
        if (parent == head->mRight) {
          head->mRight = inserted;
        }
      }

      RebalanceTreeAfterInsert(tree, inserted);
      ++tree.mSize;
    }

    /**
     * Address family:
     * - 0x00431B00 (FUN_00431B00)
     * - 0x00432B60 (FUN_00432B60)
     *
     * What it does:
     * Inserts one technique definition node into the fidelity-definition tree.
     */
    TechniqueNode* InsertTechniqueNode(TechniqueTree& tree, const msvc8::string& techniqueName)
    {
      if (tree.mSize > kMaxTechniqueTreeNodeCount) {
        ThrowMapSetTooLong();
      }

      TechniqueNode* const head = tree.mHead;
      TechniqueNode* parent = head;
      TechniqueNode* node = head->mParent;
      bool insertLeft = true;
      while (node != nullptr && node->mIsNil == 0u) {
        parent = node;
        if (CompareLegacyStrings(techniqueName, node->mTechnique.mName) < 0) {
          insertLeft = true;
          node = node->mLeft;
        } else {
          insertLeft = false;
          node = node->mRight;
        }
      }

      void* const storage = ::operator new(sizeof(TechniqueNode));
      auto* const inserted = static_cast<TechniqueNode*>(storage);
      inserted->mLeft = head;
      inserted->mParent = parent;
      inserted->mRight = head;
      inserted->mColor = kTreeColorRed;
      inserted->mIsNil = 0;
      inserted->mPadD6[0] = 0;
      inserted->mPadD6[1] = 0;
      try {
        ::new (static_cast<void*>(&inserted->mTechnique)) CD3DEffect::Technique(techniqueName);
      } catch (...) {
        ::operator delete(inserted);
        throw;
      }

      LinkInsertedTreeNode(tree, parent, inserted, insertLeft);
      return inserted;
    }

    /**
     * Address family:
     * - 0x00431B00 (FUN_00431B00)
     * - 0x00431C60 (FUN_00431C60)
     *
     * What it does:
     * Returns one exact-match technique-definition node and inserts a new node
     * when that definition is currently missing.
     */
    TechniqueNode* FindOrInsertTechniqueNode(TechniqueTree& tree, const msvc8::string& techniqueName)
    {
      TechniqueNode* const existing = FindTechniqueNode(tree, techniqueName);
      if (existing != tree.mHead) {
        return existing;
      }

      return InsertTechniqueNode(tree, techniqueName);
    }

    void FinalizeTechniqueDefinitionsInOrder(TechniqueNode* const node, TechniqueNode* const head)
    {
      if (node == nullptr || node == head || node->mIsNil != 0u) {
        return;
      }

      FinalizeTechniqueDefinitionsInOrder(node->mLeft, head);
      node->mTechnique.FinalizeMissingImplementations();
      FinalizeTechniqueDefinitionsInOrder(node->mRight, head);
    }

    [[nodiscard]] bool IsDiskFileInfoNotOlder(const SDiskFileInfo& lhs, const SDiskFileInfo& rhs) noexcept
    {
      const LONG comparison = ::CompareFileTime(&lhs.mLastWriteTime, &rhs.mLastWriteTime);
      return comparison >= 0;
    }

    template <typename NodeT>
    [[nodiscard]] NodeT* FindOrInsertAnnotationNode(
      Implementation::AnnotationTreeMap<NodeT>& map,
      const msvc8::string& key
    )
    {
      NodeT* const existing = FindAnnotationNode(map, key);
      if (existing != map.mHead) {
        return existing;
      }

      if (map.mSize > kMaxAnnotationTreeNodeCount) {
        ThrowMapSetTooLong();
      }

      NodeT* const head = map.mHead;
      NodeT* parent = head;
      NodeT* node = head->mParent;
      bool insertLeft = true;
      while (node != nullptr && node->mIsNil == 0u) {
        parent = node;
        if (CompareLegacyStrings(key, node->mKey) < 0) {
          insertLeft = true;
          node = node->mLeft;
        } else {
          insertLeft = false;
          node = node->mRight;
        }
      }

      auto* const inserted = new NodeT{};
      try {
        inserted->mKey.assign(key, 0U, msvc8::string::npos);
      } catch (...) {
        delete inserted;
        throw;
      }

      inserted->mParent = parent;
      inserted->mLeft = head;
      inserted->mRight = head;
      inserted->mColor = kTreeColorRed;
      inserted->mIsNil = 0;

      LinkInsertedTreeNode(map, parent, inserted, insertLeft);
      return inserted;
    }

    [[nodiscard]] std::int32_t ResolveGraphicsFidelityIndex()
    {
      return graphics_Fidelity;
    }

    /**
     * Address: 0x0042D500 (FUN_0042D500)
     *
     * What it does:
     * Assigns one technique shared-handle lane, preserving shared-count semantics.
     */
    CD3DEffect::SharedHandle<gpg::gal::EffectTechniqueD3D9>& AssignTechniqueHandle(
      CD3DEffect::SharedHandle<gpg::gal::EffectTechniqueD3D9>& destination,
      const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9>& source
    )
    {
      SharedHandleAsBoost(destination) = source;
      return destination;
    }

  } // namespace

  /**
   * Address: 0x0042BB80 (FUN_0042BB80)
   * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one technique implementation lane with empty annotation trees.
   */
  CD3DEffect::Technique::Implementation::Implementation()
  {
    (void)InitializeIntAnnotationTreeStorage(&mIntegerAnnotations);

    StringAnnotationNode* const stringHead = AllocateStringAnnotationSentinel();
    InitializeSentinelMap(mStringAnnotations, stringHead);
  }

  /**
   * Address: 0x0042BC10 (FUN_0042BC10)
   * Mangled: ??0Implementation@Technique@CD3DEffect@Moho@@QAE@@Z_0
   *
   * What it does:
   * Initializes one implementation lane and copies one lane-name string.
   */
  CD3DEffect::Technique::Implementation::Implementation(const msvc8::string& implementationName)
  {
    mName.assign(implementationName, 0U, msvc8::string::npos);

    (void)InitializeIntAnnotationTreeStorage(&mIntegerAnnotations);

    StringAnnotationNode* const stringHead = AllocateStringAnnotationSentinel();
    InitializeSentinelMap(mStringAnnotations, stringHead);
  }

  /**
   * Address: 0x0042BCB0 (FUN_0042BCB0)
   * Mangled: ??1Implementation@Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Destroys both annotation trees and releases the implementation name.
   */
  CD3DEffect::Technique::Implementation::~Implementation()
  {
    DestroyStringAnnotationTreeStorage(mStringAnnotations);
    DestroyIntegerAnnotationTreeStorage(mIntegerAnnotations);
    mName.tidy(true, 0U);
  }

  /**
   * Address: 0x0042C1D0 (FUN_0042C1D0)
   *
   * Implementation const &
   *
   * What it does:
   * Copies the lane name and both annotation trees from the source lane.
   */
  CD3DEffect::Technique::Implementation& CD3DEffect::Technique::Implementation::operator=(
    const Implementation& other
  )
  {
    mName.assign(other.mName, 0U, msvc8::string::npos);
    AssignIntegerAnnotationTree(mIntegerAnnotations, other.mIntegerAnnotations);
    AssignStringAnnotationTree(mStringAnnotations, other.mStringAnnotations);
    return *this;
  }

  /**
   * Address: 0x0042BDC0 (FUN_0042BDC0)
   *
   * What it does:
   * Looks up one integer annotation by key and writes the found value.
   */
  bool CD3DEffect::Technique::Implementation::TryGetIntegerAnnotation(
    const msvc8::string& annotationName,
    std::int32_t* const outValue
  ) const
  {
    IntAnnotationNode* const node = FindIntAnnotationNodeBridge(mIntegerAnnotations, annotationName);
    if (node == mIntegerAnnotations.mHead) {
      return false;
    }

    *outValue = node->mValue;
    return true;
  }

  /**
   * Address: 0x0042BE00 (FUN_0042BE00)
   *
   * What it does:
   * Looks up one string annotation by key and copies the stored value.
   */
  bool CD3DEffect::Technique::Implementation::TryGetStringAnnotation(
    const msvc8::string& annotationName,
    msvc8::string* const outValue
  ) const
  {
    StringAnnotationNode* const node = FindAnnotationNode(mStringAnnotations, annotationName);
    if (node == mStringAnnotations.mHead) {
      return false;
    }

    outValue->assign(node->mValue, 0U, msvc8::string::npos);
    return true;
  }

  void CD3DEffect::Technique::Implementation::UnknownVirtualSlot()
  {
  }

  /**
   * Address: 0x0042BE40 (FUN_0042BE40)
   * Mangled: ??0Technique@CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one technique with name text and three implementation lanes.
   */
  CD3DEffect::Technique::Technique(const msvc8::string& techniqueName)
  {
    mName.assign(techniqueName, 0U, msvc8::string::npos);

    Implementation* const lanes = GetImplementationLanes();
    std::uint32_t constructedCount = 0;
    try {
      for (; constructedCount < 3U; ++constructedCount) {
        ::new (static_cast<void*>(lanes + constructedCount)) Implementation();
      }
    } catch (...) {
      while (constructedCount > 0U) {
        --constructedCount;
        lanes[constructedCount].~Implementation();
      }
      throw;
    }
  }

  /**
   * Address: 0x0042BEC0 (FUN_0042BEC0)
   * Mangled: ??1Technique@CD3DEffect@Moho@@UAE@XZ
   *
   * What it does:
   * Destroys all implementation lanes and releases the technique name.
   */
  CD3DEffect::Technique::~Technique()
  {
    Implementation* const lanes = GetImplementationLanes();
    for (std::int32_t index = 2; index >= 0; --index) {
      lanes[index].~Implementation();
    }

    mName.tidy(true, 0U);
  }

  /**
   * Address: 0x0042BF40 (FUN_0042BF40)
   *
   * What it does:
   * Fills missing fidelity lanes by cloning the first available implementation.
   */
  void CD3DEffect::Technique::FinalizeMissingImplementations()
  {
    Implementation* const lanes = GetImplementationLanes();
    if (HasConstructedLaneName(lanes[0]) && HasConstructedLaneName(lanes[1]) && HasConstructedLaneName(lanes[2])) {
      return;
    }

    std::optional<Implementation> sharedFallback{};
    auto resolveSourceLane = [&](const std::uint32_t primary, const std::uint32_t secondary, const std::uint32_t tertiary) -> const Implementation* {
      if (HasConstructedLaneName(lanes[primary])) {
        return &lanes[primary];
      }
      if (HasConstructedLaneName(lanes[secondary])) {
        return &lanes[secondary];
      }
      if (HasConstructedLaneName(lanes[tertiary])) {
        return &lanes[tertiary];
      }

      if (!sharedFallback.has_value()) {
        sharedFallback.emplace(mName);
      }
      return &sharedFallback.value();
    };

    const Implementation* const lane0Source = resolveSourceLane(0U, 1U, 2U);
    lanes[0] = *lane0Source;

    const Implementation* const lane1Source = resolveSourceLane(1U, 0U, 2U);
    lanes[1] = *lane1Source;

    const Implementation* const lane2Source = resolveSourceLane(2U, 1U, 0U);
    lanes[2] = *lane2Source;
  }

  CD3DEffect::Technique::Implementation* CD3DEffect::Technique::GetImplementationLanes() noexcept
  {
    return reinterpret_cast<Implementation*>(mImplementationStorage);
  }

  const CD3DEffect::Technique::Implementation* CD3DEffect::Technique::GetImplementationLanes() const noexcept
  {
    return reinterpret_cast<const Implementation*>(mImplementationStorage);
  }

  /**
   * Address: 0x0042C430 (FUN_0042C430)
   * Mangled: ??0CD3DEffect@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one effect object with empty technique tree and cleared shared handles.
   */
  CD3DEffect::CD3DEffect()
    : mAttachedLinks(nullptr)
    , mTechniques{}
    , mName{}
    , mFile{}
    , mEffect{}
    , mCurrentTechnique{}
  {
    TechniqueNode* const techniqueHead = AllocateTechniqueSentinel();
    InitializeTechniqueTree(mTechniques, techniqueHead);
  }

  /**
   * Address: 0x0042C520 (FUN_0042C520)
   * Address: 0x00440BA0 (FUN_00440BA0, deleting thunk)
   * Mangled: ??1CD3DEffect@Moho@@QAE@XZ
   *
   * What it does:
   * Releases effect/technique shared handles, clears metadata strings, destroys
   * technique tree storage, and unlinks attached callback links.
   */
  CD3DEffect::~CD3DEffect()
  {
    (void)ReleaseSharedHandle(&mCurrentTechnique);
    (void)ReleaseSharedHandle(&mEffect);

    mFile.tidy(true, 0U);
    mName.tidy(true, 0U);

    (void)DestroyTechniqueTreeStorage(mTechniques);

    while (mAttachedLinks != nullptr) {
      AttachedLink* const detached = mAttachedLinks;
      mAttachedLinks = detached->mNext;
      detached->mLinkLane = nullptr;
      detached->mNext = nullptr;
    }
  }

  /**
   * Address: 0x0042C3D0 (FUN_0042C3D0, Moho::CON_d3d_AntiAliasingSamples)
   *
   * What it does:
   * Parses one sample-count argument and forwards it to the active D3D device.
   */
  void CD3DEffect::CON_d3d_AntiAliasingSamples(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);
    if (args.Count() != 2U) {
      return;
    }

    const msvc8::string* const sampleCountText = args.At(1U);
    if (sampleCountText == nullptr) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    device->SetAntiAliasingSamples(std::atoi(sampleCountText->c_str()));
  }

  /**
   * Address: 0x0042C650 (FUN_0042C650)
   * Mangled: ?InitEffectFromFile@CD3DEffect@Moho@@QAE_NPBD@Z
   *
   * What it does:
   * Loads one effect source file, merges compatibility preamble state,
   * creates one gal effect object, and rebuilds fidelity definitions.
   */
  bool CD3DEffect::InitEffectFromFile(const char* const effectFilePath)
  {
    struct ScopedEffectContext final
    {
      using Storage = std::aligned_storage_t<0x64, alignof(void*)>;

      ~ScopedEffectContext()
      {
        if (context != nullptr) {
          context->~EffectContext();
          context = nullptr;
        }
      }

      Storage storage{};
      gpg::gal::EffectContext* context = nullptr;
    };

    const msvc8::string engineVersion = GetEngineVersion();
    SharedHandleAsBoost(mEffect).reset();

    try {
      gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
      const gpg::gal::DeviceContext* const deviceContext = (device != nullptr) ? device->GetDeviceContext() : nullptr;
      const char* const compatResourcePath =
        (deviceContext != nullptr && deviceContext->mDeviceType == 2)
          ? "/effects/d3d10states.compat"
          : "/effects/d3d9states.compat";

      FILE_EnsureWaitHandleSet();
      FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
      if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
        return false;
      }

      msvc8::string compatPath{};
      (void)waitHandleSet->mHandle->FindFile(&compatPath, compatResourcePath, nullptr);
      const gpg::MemBuffer<const char> compatStateBuffer = DISK_MemoryMapFile(compatPath.c_str());
      const msvc8::string cacheDirectory = USER_GetAppCacheDir();
      const msvc8::string effectBaseName = FILE_Base(effectFilePath, true);

      mName.assign(effectBaseName, 0U, msvc8::string::npos);
      mFile.assign(effectFilePath, std::char_traits<char>::length(effectFilePath));

      SDiskFileInfo sourceInfo{};
      (void)waitHandleSet->GetFileInfo(mFile.c_str(), &sourceInfo, false);

      const msvc8::string cachePath = cacheDirectory + "/" + mName + "." + engineVersion;
      SDiskFileInfo cacheInfo{};
      bool useCachePayload = false;
      if (waitHandleSet->GetFileInfo(cachePath.c_str(), &cacheInfo, false)) {
        useCachePayload = IsDiskFileInfoNotOlder(cacheInfo, sourceInfo);
      }

      const gpg::MemBuffer<const char> effectSourceBuffer = DISK_MemoryMapFile(mFile.c_str());
      const std::size_t compatByteCount = compatStateBuffer.Size();
      const std::size_t effectByteCount = effectSourceBuffer.Size();
      gpg::MemBuffer<char> mergedBuffer = gpg::AllocMemBuffer(compatByteCount + effectByteCount);
      if (compatByteCount > 0U) {
        std::memcpy(
          mergedBuffer.GetPtr(0U, 0U),
          compatStateBuffer.GetPtr(0U, 0U),
          compatByteCount
        );
      }
      if (effectByteCount > 0U) {
        std::memcpy(
          mergedBuffer.GetPtr(compatByteCount, 0U),
          effectSourceBuffer.GetPtr(0U, 0U),
          effectByteCount
        );
      }

      msvc8::vector<gpg::gal::EffectMacro> effectMacros{};
      ScopedEffectContext scopedContext{};
      scopedContext.context = ::new (&scopedContext.storage) gpg::gal::EffectContext(
        useCachePayload,
        mFile.c_str(),
        cachePath.c_str(),
        mergedBuffer,
        effectMacros
      );

      boost::shared_ptr<gpg::gal::Effect> createdEffect = gpg::gal::Effect::Create(*scopedContext.context);
      struct EffectAliasDeleter
      {
        explicit EffectAliasDeleter(const boost::shared_ptr<gpg::gal::Effect>& ownerEffect)
          : owner(ownerEffect)
        {}

        void operator()(gpg::gal::EffectD3D9*) const
        {
        }

        boost::shared_ptr<gpg::gal::Effect> owner;
      };

      boost::shared_ptr<gpg::gal::EffectD3D9> effectHandle(
        reinterpret_cast<gpg::gal::EffectD3D9*>(createdEffect.get()),
        EffectAliasDeleter(createdEffect)
      );
      SharedHandleAsBoost(mEffect) = effectHandle;

      ClearTechniqueTreeNodes(mTechniques);

      msvc8::vector<msvc8::string> techniqueImplementationNames{};
      EnumerateValidTechniques(techniqueImplementationNames);
      for (const msvc8::string& implementationName : techniqueImplementationNames) {
        msvc8::string abstractTechniqueName{};
        const msvc8::string abstractTechniqueToken("abstractTechnique", 17U);
        if (!GetImplAnnotation(&abstractTechniqueName, implementationName, abstractTechniqueToken)) {
          abstractTechniqueName.assign(implementationName, 0U, msvc8::string::npos);
        }

        TechniqueNode* const definition = FindOrInsertTechniqueNode(mTechniques, abstractTechniqueName);
        Technique::Implementation* const lanes = definition->mTechnique.GetImplementationLanes();
        if (HasConstructedLaneName(lanes[0]) && HasConstructedLaneName(lanes[1]) && HasConstructedLaneName(lanes[2])) {
          gpg::Warnf(
            "technique %s in effect %s has been finalized (attempt to define a redundant fidelity)",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        if (CompareLegacyStrings(abstractTechniqueName, implementationName) == 0) {
          Technique::Implementation implementation(abstractTechniqueName);
          lanes[0] = implementation;
          lanes[1] = implementation;
          lanes[2] = implementation;
          continue;
        }

        std::int32_t fidelityIndex = -1;
        const msvc8::string fidelityToken("fidelity", 8U);
        (void)GetImplAnnotation(&fidelityIndex, implementationName, fidelityToken);
        if (fidelityIndex < 0 || fidelityIndex > 2) {
          gpg::Warnf(
            "technique %s in effect %s has incomplete definition",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        if (HasConstructedLaneName(lanes[fidelityIndex])) {
          gpg::Warnf(
            "redundant implementation for technique %s in effect %s",
            abstractTechniqueName.c_str(),
            mName.c_str()
          );
          continue;
        }

        Technique::Implementation implementation(implementationName);
        lanes[fidelityIndex] = implementation;
      }

      FinalizeTechniqueDefinitionsInOrder(mTechniques.mHead->mParent, mTechniques.mHead);
      return true;
    } catch (const std::exception& exception) {
      gpg::Warnf("%s: %s", effectFilePath, exception.what());
      return false;
    }
  }

  /**
   * Address: 0x00431C60 (FUN_00431C60)
   *
   * Technique const &
   *
   * What it does:
   * Resolves one exact fidelity-definition node for the supplied technique.
   */
  CD3DEffect::TechniqueNode* CD3DEffect::GetFidelityDefinitions(const Technique& technique)
  {
    TechniqueNode* const lowerBound = LowerBoundTechniqueNode(mTechniques, technique.mName);
    if (lowerBound == mTechniques.mHead || CompareLegacyStrings(technique.mName, lowerBound->mTechnique.mName) < 0) {
      return mTechniques.mHead;
    }

    return lowerBound;
  }

  /**
   * Address: 0x0042DB30 (FUN_0042DB30)
   *
   * What it does:
   * Queries the current effect for valid techniques and appends their names.
   */
  void CD3DEffect::EnumerateValidTechniques(msvc8::vector<msvc8::string>& outTechniqueNames)
  {
    msvc8::vector<boost::shared_ptr<gpg::gal::EffectTechniqueD3D9>> techniques{};
    (void)SharedHandleAsBoost(mEffect)->GetTechniques(techniques);

    for (const boost::shared_ptr<gpg::gal::EffectTechniqueD3D9>& technique : techniques) {
      outTechniqueNames.push_back(*technique->GetName());
    }
  }

  /**
   * Address: 0x0042D290 (FUN_0042D290, ?SetTechnique@CD3DEffect@Moho@@QAEXPBD@Z)
   *
   * What it does:
   * Selects one technique on the backing gal effect, preferring the current
   * fidelity implementation lane when present.
   */
  void CD3DEffect::SetTechnique(const char* const techniqueName)
  {
    const msvc8::string lookupName(techniqueName, std::char_traits<char>::length(techniqueName));
    const Technique lookupTechnique(lookupName);
    TechniqueNode* const definition = GetFidelityDefinitions(lookupTechnique);

    auto& effect = SharedHandleAsBoost(mEffect);
    auto selectAndWarnInvalid = [&]() {
      AssignTechniqueHandle(mCurrentTechnique, effect->SetTechnique(techniqueName));
      gpg::Debugf(
        "technique %s in effect %s has an invalid fidelity definition",
        techniqueName,
        mName.c_str()
      );
    };

    if (definition == mTechniques.mHead) {
      selectAndWarnInvalid();
      return;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation* const lanes = definition->mTechnique.GetImplementationLanes();
    Technique::Implementation& selectedLane = lanes[fidelityIndex];
    if (selectedLane.mName.myRes == 0U) {
      selectAndWarnInvalid();
      return;
    }

    AssignTechniqueHandle(mCurrentTechnique, effect->SetTechnique(selectedLane.mName.c_str()));
  }

  /**
   * Address: 0x0042D580 (FUN_0042D580)
   * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@1@Z
   *
   * What it does:
   * Reads one integer annotation from one implementation technique lane.
   */
  bool CD3DEffect::GetImplAnnotation(
    std::int32_t* const outValue,
    const msvc8::string& implementationName,
    const msvc8::string& annotationName
  )
  {
    const auto& effect = SharedHandleAsBoost(mEffect);
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique(implementationName.c_str());
    if (!technique) {
      return false;
    }
    return technique->GetAnnotationInt(outValue, annotationName);
  }

  /**
   * Address: 0x0042D640 (FUN_0042D640)
   * Mangled: ?GetIntegerAnnotation@CD3DEffect@Moho@@QAEHABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@0H@Z
   *
   * What it does:
   * Returns one integer annotation for the selected technique/fidelity lane,
   * resolving from implementation annotation when cache is missing.
   */
  std::int32_t CD3DEffect::GetIntegerAnnotation(
    const msvc8::string& techniqueName,
    const msvc8::string& annotationName,
    const std::int32_t defaultValue
  )
  {
    (void)defaultValue;
    std::int32_t resolvedValue = 0;

    const auto& effect = SharedHandleAsBoost(mEffect);
    if (!effect) {
      gpg::Warnf("attempt to retrieve annotation from invalid effect");
      return resolvedValue;
    }

    const Technique lookupTechnique(techniqueName);
    TechniqueNode* const definition = GetFidelityDefinitions(lookupTechnique);
    if (definition == mTechniques.mHead) {
      gpg::Warnf("attempt to retrieve annotation from unknown technique %s", techniqueName.c_str());
      return resolvedValue;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation& lane = definition->mTechnique.GetImplementationLanes()[fidelityIndex];
    if (!lane.TryGetIntegerAnnotation(annotationName, &resolvedValue)) {
      (void)GetImplAnnotation(&resolvedValue, lane.mName, annotationName);
      IntAnnotationNode* const annotationNode = FindOrInsertAnnotationNode(lane.mIntegerAnnotations, annotationName);
      annotationNode->mValue = resolvedValue;
    }

    return resolvedValue;
  }

  /**
   * Address: 0x0042D780 (FUN_0042D780)
   * Mangled: ?GetImplAnnotation@CD3DEffect@Moho@@AAE_NAAV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@1@Z
   *
   * What it does:
   * Reads one string annotation from one implementation technique lane.
   */
  bool CD3DEffect::GetImplAnnotation(
    msvc8::string* const outValue,
    const msvc8::string& implementationName,
    const msvc8::string& annotationName
  )
  {
    const auto& effect = SharedHandleAsBoost(mEffect);
    boost::shared_ptr<gpg::gal::EffectTechniqueD3D9> technique = effect->SetTechnique(implementationName.c_str());
    if (!technique) {
      return false;
    }
    return technique->GetAnnotationString(outValue, annotationName);
  }

  /**
   * Address: 0x0042D840 (FUN_0042D840)
   * Mangled: ?GetStringAnnotation@CD3DEffect@Moho@@QAE?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABV34@00@Z
   *
   * What it does:
   * Returns one string annotation for the selected technique/fidelity lane,
   * resolving from implementation annotation when cache is missing.
   */
  msvc8::string CD3DEffect::GetStringAnnotation(
    const msvc8::string& techniqueName,
    const msvc8::string& annotationName,
    const msvc8::string& defaultValue
  )
  {
    msvc8::string resolvedValue{};
    resolvedValue.assign(defaultValue, 0U, msvc8::string::npos);

    const auto& effect = SharedHandleAsBoost(mEffect);
    if (!effect) {
      gpg::Warnf("attempt to retrieve annotation from invalid effect");
      return resolvedValue;
    }

    const Technique lookupTechnique(techniqueName);
    TechniqueNode* const definition = GetFidelityDefinitions(lookupTechnique);
    if (definition == mTechniques.mHead) {
      gpg::Warnf("attempt to retrieve annotation from unknown technique %s", techniqueName.c_str());
      return resolvedValue;
    }

    const std::int32_t fidelityIndex = ResolveGraphicsFidelityIndex();
    Technique::Implementation& lane = definition->mTechnique.GetImplementationLanes()[fidelityIndex];
    if (!lane.TryGetStringAnnotation(annotationName, &resolvedValue)) {
      (void)GetImplAnnotation(&resolvedValue, lane.mName, annotationName);
      StringAnnotationNode* const annotationNode = FindOrInsertAnnotationNode(lane.mStringAnnotations, annotationName);
      annotationNode->mValue.assign(resolvedValue, 0U, msvc8::string::npos);
    }

    return resolvedValue;
  }

  /**
   * Address: 0x00437E90 (FUN_00437E90, ?GetBaseEffect@CD3DEffect@Moho@@QAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Returns a shared handle copy of the current base GAL effect lane.
   */
  boost::shared_ptr<gpg::gal::EffectD3D9> CD3DEffect::GetBaseEffect()
  {
    return SharedHandleAsBoost(mEffect);
  }

  /**
   * Address: 0x0042DA30 (FUN_0042DA30, ?SetTexture@CD3DEffect@Moho@@QAEXPBDV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@@Z)
   *
   * What it does:
   * Resolves one effect variable by name and binds one texture handle (or
   * clears the slot when texture is null).
   */
  void CD3DEffect::SetTexture(const char* const variableName, boost::shared_ptr<ID3DTextureSheet> texture)
  {
    const auto& effect = SharedHandleAsBoost(mEffect);
    boost::shared_ptr<gpg::gal::EffectVariableD3D9> variable = effect->SetMatrix(variableName);

    if (texture) {
      ID3DTextureSheet::TextureHandle textureHandle{};
      texture->GetTexture(textureHandle);
      variable->SetTexture(textureHandle);
      return;
    }

    variable->SetTexture(ID3DTextureSheet::TextureHandle{});
  }
} // namespace moho
