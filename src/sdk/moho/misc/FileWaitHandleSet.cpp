#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/CZipFile.h"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

#include "gpg/core/streams/FileStream.h"
#include "lua/LuaObject.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/StartupHelpers.h"

namespace moho
{
  msvc8::string WIN_GetLastError();
}

namespace
{
  moho::FWaitHandleSet sFWaitHandleSet{};
  moho::FWaitHandleSet* sPFWaitHandleSet = nullptr;
  std::once_flag sFileWaitHandleSetInitOnce;
  thread_local std::unordered_map<const moho::FWHSThreadStateRuntime*, msvc8::string*> sDiskThreadStateStrings{};
  constexpr const char* kDiskFindFilesHelpText =
    "files = DiskFindFiles(directory, pattern)\nreturns a list of files in a directory";
  constexpr const char* kDiskGetFileInfoHelpText =
    "info = DiskGetFileInfo(filename)\n"
    "returns a table describing the given file, or false if the file doesn't exist.\n"
    "    info.IsFolder -- true if the filename refers to a folder\n"
    "    info.IsReadOnly -- true if file is read-only\n"
    "    info.SizeBytes -- size of file in bytes\n"
    "    info.LastWriteTime -- timestamp of last write to file";
  constexpr const char* kDiskToLocalHelpText =
    "localPath = DiskToLocal(SysOrLocalPath)\n"
    "Converts a system path to a local path. Leaves\n"
    "path alone if already local.";
  constexpr const char* kBasenameHelpText =
    "base = Basename(fullPath,stripExtension?) -- return the last component of a path";
  constexpr const char* kDirnameHelpText =
    "base = Dirname(fullPath) -- return a path with trailing filename removed";
  constexpr const char* kFileCollapsePathHelpText =
    "path = FileCollapsePath(fullPath) -- collapse out any intermediate /./ or /../ directory names from a path";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  /**
   * Address: 0x0045B210 (FUN_0045B210, Moho::CDiskThreadState::Create)
   *
   * What it does:
   * Initializes one disk-thread-state TSS slot descriptor used by
   * `FWaitHandleSet::ErrorString`.
   */
  void CreateDiskThreadStateRuntime(moho::FWHSThreadStateRuntime& runtime)
  {
    runtime.mTss = &runtime;
  }

  /**
   * Address: 0x0045C110 (FUN_0045C110, onExit)
   *
   * What it does:
   * Releases one heap-allocated disk thread-state error string value.
   */
  void DestroyDiskThreadStateString(msvc8::string* const value)
  {
    delete value;
  }

  void CleanupDiskThreadStateValue(const moho::FWHSThreadStateRuntime& runtime)
  {
    const auto it = sDiskThreadStateStrings.find(&runtime);
    if (it != sDiskThreadStateStrings.end()) {
      DestroyDiskThreadStateString(it->second);
      sDiskThreadStateStrings.erase(it);
    }
  }

  [[nodiscard]]
  msvc8::string* GetOrCreateDiskThreadStateValue(moho::FWHSThreadStateRuntime& runtime)
  {
    if (msvc8::string*& slot = sDiskThreadStateStrings[&runtime]; slot == nullptr) {
      slot = new msvc8::string();
    }
    return sDiskThreadStateStrings[&runtime];
  }

  /**
   * Address: 0x00456B40 (FUN_00456B40, sub_456B40)
   *
   * What it does:
   * Creates one nested `Flags` table, stores it under the owner table at
   * `ownerTableIndex`, and returns a stack view for the nested table.
   */
  [[nodiscard]] LuaPlus::LuaStackObject CreateFlagsTableStackObject(
    LuaPlus::LuaState* const state, const int ownerTableIndex
  )
  {
    lua_newtable(state->m_state);
    lua_pushstring(state->m_state, "Flags");
    lua_pushvalue(state->m_state, lua_gettop(state->m_state) - 1);
    lua_settable(state->m_state, ownerTableIndex);
    return LuaPlus::LuaStackObject(state, lua_gettop(state->m_state));
  }

  boost::mutex& EnsureFileWaitSetMutex(moho::FWHSLockRuntime& lockRuntime)
  {
    if (lockRuntime.mMutex == nullptr) {
      lockRuntime.mMutex = new boost::mutex();
    }
    return *lockRuntime.mMutex;
  }

  [[nodiscard]]
  int ComparePathViews(const std::string_view lhs, const std::string_view rhs)
  {
    const std::size_t sharedCount = std::min(lhs.size(), rhs.size());
    const int sharedResult = sharedCount == 0 ? 0 : std::memcmp(lhs.data(), rhs.data(), sharedCount);
    if (sharedResult != 0) {
      return sharedResult;
    }
    if (lhs.size() == rhs.size()) {
      return 0;
    }
    return lhs.size() < rhs.size() ? -1 : 1;
  }

  [[nodiscard]]
  int CompareCanonicalPaths(const msvc8::string& lhs, const msvc8::string& rhs)
  {
    return ComparePathViews(lhs.view(), rhs.view());
  }

  /**
   * Address: 0x0045F3F0 (FUN_0045F3F0, sub_45F3F0)
   *
   * What it does:
   * Releases one legacy string's heap buffer when present and restores empty
   * SSO state.
   */
  void ResetLegacyStringStorage(msvc8::string& value)
  {
    value.tidy(true, 0U);
  }

  [[nodiscard]]
  void* AllocateCheckedArrayStorage(const std::uint32_t count, const std::size_t elementSize)
  {
    if (count != 0u &&
        static_cast<std::size_t>(count) > (std::numeric_limits<std::size_t>::max() / elementSize)) {
      throw std::bad_alloc();
    }
    return ::operator new(static_cast<std::size_t>(count) * elementSize);
  }

  /**
   * Address: 0x0045F260 (FUN_0045F260, sub_45F260)
   *
   * What it does:
   * Allocates raw storage for one-or-more zip-entry map nodes with overflow
   * guard semantics.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* AllocateZipEntryMapNodes(const std::uint32_t count)
  {
    return static_cast<moho::FWHSZipEntryMapNode*>(
      AllocateCheckedArrayStorage(count, sizeof(moho::FWHSZipEntryMapNode))
    );
  }

  /**
   * Address: 0x0045F380 (FUN_0045F380, sub_45F380)
   *
   * What it does:
   * Allocates raw storage for one-or-more file-info map nodes with overflow
   * guard semantics.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* AllocateFileInfoMapNodes(const std::uint32_t count)
  {
    return static_cast<moho::FWHSFileInfoMapNode*>(
      AllocateCheckedArrayStorage(count, sizeof(moho::FWHSFileInfoMapNode))
    );
  }

  /**
   * Address: 0x0045E320 (FUN_0045E320, sub_45E320)
   *
   * What it does:
   * Allocates raw storage for one file-info map node.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* AllocateOneFileInfoMapNode()
  {
    return AllocateFileInfoMapNodes(1u);
  }

  [[nodiscard]]
  bool IsZipMapSentinel(const moho::FWHSZipEntryMapNode* const node)
  {
    return node == nullptr || node->mIsNil != 0;
  }

  [[nodiscard]]
  bool IsFileInfoMapSentinel(const moho::FWHSFileInfoMapNode* const node)
  {
    return node == nullptr || node->mIsNil != 0;
  }

  /**
   * Address: 0x0045C8F0 (FUN_0045C8F0, std::map_string_FWHSEntry::_Lbound)
   *
   * What it does:
   * Returns the first zip-entry node whose key is not less than the canonical
   * path.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipEntryLowerBound(
    const moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    const msvc8::string& canonicalPath
  )
  {
    moho::FWHSZipEntryMapNode* result = map.mHead;
    if (result == nullptr) {
      return nullptr;
    }

    moho::FWHSZipEntryMapNode* parent = result->mParent;
    while (!IsZipMapSentinel(parent)) {
      if (CompareCanonicalPaths(parent->mCanonicalPath, canonicalPath) >= 0) {
        result = parent;
        parent = parent->mLeft;
      } else {
        parent = parent->mRight;
      }
    }
    return result;
  }

  /**
   * Address: 0x0045AF50 (FUN_0045AF50, std::map_string_FWHSEntry::find)
   *
   * What it does:
   * Finds one exact canonical-path match in the zip-entry map and returns the
   * map head sentinel when not found.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipEntryFind(
    const moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    const msvc8::string& canonicalPath
  )
  {
    moho::FWHSZipEntryMapNode* const lowerBound = ZipEntryLowerBound(map, canonicalPath);
    if (lowerBound == nullptr || lowerBound == map.mHead) {
      return map.mHead;
    }
    return CompareCanonicalPaths(canonicalPath, lowerBound->mCanonicalPath) < 0 ? map.mHead : lowerBound;
  }

  /**
   * Address: 0x0045D080 (FUN_0045D080, std::map_string_SDiskFileInfo::_Lbound)
   *
   * What it does:
   * Returns the first file-info node whose key is not less than the canonical
   * path.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoLowerBound(
    const moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map,
    const msvc8::string& canonicalPath
  )
  {
    moho::FWHSFileInfoMapNode* result = map.mHead;
    if (result == nullptr) {
      return nullptr;
    }

    moho::FWHSFileInfoMapNode* parent = result->mParent;
    while (!IsFileInfoMapSentinel(parent)) {
      if (CompareCanonicalPaths(parent->mCanonicalPath, canonicalPath) >= 0) {
        result = parent;
        parent = parent->mLeft;
      } else {
        parent = parent->mRight;
      }
    }
    return result;
  }

  /**
   * Address: 0x0045B160 (FUN_0045B160, std::map_string_SDiskFileInfo::find)
   *
   * What it does:
   * Finds one exact canonical-path match in the file-info map and returns the
   * map head sentinel when not found.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoFind(
    const moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map,
    const msvc8::string& canonicalPath
  )
  {
    moho::FWHSFileInfoMapNode* const lowerBound = FileInfoLowerBound(map, canonicalPath);
    if (lowerBound == nullptr || lowerBound == map.mHead) {
      return map.mHead;
    }
    return CompareCanonicalPaths(canonicalPath, lowerBound->mCanonicalPath) < 0 ? map.mHead : lowerBound;
  }

  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoMapHead(const moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map)
  {
    return map.mHead;
  }

  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoMapRoot(const moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map)
  {
    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    if (IsFileInfoMapSentinel(head)) {
      return head;
    }
    return head->mParent;
  }

  [[nodiscard]]
  bool IsFileInfoNodeBlack(const moho::FWHSFileInfoMapNode* const node)
  {
    return IsFileInfoMapSentinel(node) || node->mColor != 0;
  }

  [[nodiscard]]
  bool IsFileInfoNodeRed(const moho::FWHSFileInfoMapNode* const node)
  {
    return !IsFileInfoNodeBlack(node);
  }

  void SetFileInfoNodeBlack(moho::FWHSFileInfoMapNode* const node)
  {
    if (!IsFileInfoMapSentinel(node)) {
      node->mColor = 1;
    }
  }

  void SetFileInfoNodeRed(moho::FWHSFileInfoMapNode* const node)
  {
    if (!IsFileInfoMapSentinel(node)) {
      node->mColor = 0;
    }
  }

  void SetFileInfoNodeColor(moho::FWHSFileInfoMapNode* const node, const std::uint8_t color)
  {
    if (!IsFileInfoMapSentinel(node)) {
      node->mColor = color;
    }
  }

  /**
   * Address: 0x0045E420 (FUN_0045E420, sub_45E420)
   *
   * What it does:
   * Initializes one file-info map node payload and tree links.
   */
  moho::FWHSFileInfoMapNode* InitializeFileInfoMapNode(
    moho::FWHSFileInfoMapNode* const left,
    moho::FWHSFileInfoMapNode* const right,
    moho::FWHSFileInfoMapNode* const parent,
    moho::FWHSFileInfoMapNode* const node,
    const msvc8::string& canonicalPath,
    const moho::SDiskFileInfo& info
  )
  {
    node->mParent = parent;
    node->mLeft = left;
    node->mRight = right;
    node->mUnknown0C = 0;
    node->mCanonicalPath.assign_owned(canonicalPath.view());
    node->mUnknown2C = 0;
    node->mInfo = info;
    node->mColor = 0;
    node->mIsNil = 0;
    node->mUnknown44 = 0;
    return node;
  }

  /**
   * Address: 0x0045DFA0 (FUN_0045DFA0, sub_45DFA0)
   *
   * What it does:
   * Allocates and initializes one file-info map node for insertion.
   */
  [[nodiscard]]
  std::unique_ptr<moho::FWHSFileInfoMapNode> CreateFileInfoMapNode(
    moho::FWHSFileInfoMapNode* const left,
    moho::FWHSFileInfoMapNode* const right,
    moho::FWHSFileInfoMapNode* const parent,
    const msvc8::string& canonicalPath,
    const moho::SDiskFileInfo& info
  )
  {
    moho::FWHSFileInfoMapNode* const insertedNode = ::new (AllocateOneFileInfoMapNode()) moho::FWHSFileInfoMapNode();
    std::unique_ptr<moho::FWHSFileInfoMapNode> insertedNodeOwner(insertedNode);
    (void)InitializeFileInfoMapNode(left, right, parent, insertedNodeOwner.get(), canonicalPath, info);
    return insertedNodeOwner;
  }

  /**
   * Address: 0x0045DF60 (FUN_0045DF60, sub_45DF60)
   *
   * What it does:
   * Allocates and initializes one file-info map head/sentinel node.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* CreateFileInfoMapHeadNode()
  {
    moho::FWHSFileInfoMapNode* const head = ::new (AllocateOneFileInfoMapNode()) moho::FWHSFileInfoMapNode();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mColor = 1;
    head->mIsNil = 1;
    return head;
  }

  void EnsureFileInfoMapInitialized(moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map)
  {
    if (map.mHead != nullptr) {
      return;
    }

    map.mHead = CreateFileInfoMapHeadNode();
    map.mSize = 0;
  }

  /**
   * Address: 0x0045DE20 (FUN_0045DE20, sub_45DE20)
   *
   * What it does:
   * Performs one file-info map left rotation around `pivot`.
   */
  void FileInfoMapRotateLeft(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, moho::FWHSFileInfoMapNode* const pivot
  )
  {
    if (IsFileInfoMapSentinel(pivot) || IsFileInfoMapSentinel(pivot->mRight)) {
      return;
    }

    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    moho::FWHSFileInfoMapNode* const right = pivot->mRight;

    pivot->mRight = right->mLeft;
    if (!IsFileInfoMapSentinel(right->mLeft)) {
      right->mLeft->mParent = pivot;
    }

    right->mParent = pivot->mParent;
    if (IsFileInfoMapSentinel(pivot->mParent)) {
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
   * Address: 0x0045DEC0 (FUN_0045DEC0, sub_45DEC0)
   *
   * What it does:
   * Performs one file-info map right rotation around `pivot`.
   */
  void FileInfoMapRotateRight(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, moho::FWHSFileInfoMapNode* const pivot
  )
  {
    if (IsFileInfoMapSentinel(pivot) || IsFileInfoMapSentinel(pivot->mLeft)) {
      return;
    }

    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    moho::FWHSFileInfoMapNode* const left = pivot->mLeft;

    pivot->mLeft = left->mRight;
    if (!IsFileInfoMapSentinel(left->mRight)) {
      left->mRight->mParent = pivot;
    }

    left->mParent = pivot->mParent;
    if (IsFileInfoMapSentinel(pivot->mParent)) {
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
   * Address context:
   * - 0x0045CED0 (FUN_0045CED0, sub_45CED0) insertion rebalance lane.
   *
   * What it does:
   * Restores red-black invariants after linking one file-info map node.
   */
  void FileInfoMapInsertFixup(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, moho::FWHSFileInfoMapNode* node
  )
  {
    while (!IsFileInfoMapSentinel(node->mParent) && node->mParent->mColor == 0) {
      moho::FWHSFileInfoMapNode* const parent = node->mParent;
      moho::FWHSFileInfoMapNode* const grandparent = parent->mParent;
      if (parent == grandparent->mLeft) {
        moho::FWHSFileInfoMapNode* uncle = grandparent->mRight;
        if (!IsFileInfoMapSentinel(uncle) && uncle->mColor == 0) {
          SetFileInfoNodeBlack(parent);
          SetFileInfoNodeBlack(uncle);
          SetFileInfoNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mRight) {
            node = parent;
            FileInfoMapRotateLeft(map, node);
          }
          SetFileInfoNodeBlack(node->mParent);
          SetFileInfoNodeRed(node->mParent->mParent);
          FileInfoMapRotateRight(map, node->mParent->mParent);
        }
      } else {
        moho::FWHSFileInfoMapNode* uncle = grandparent->mLeft;
        if (!IsFileInfoMapSentinel(uncle) && uncle->mColor == 0) {
          SetFileInfoNodeBlack(parent);
          SetFileInfoNodeBlack(uncle);
          SetFileInfoNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            FileInfoMapRotateRight(map, node);
          }
          SetFileInfoNodeBlack(node->mParent);
          SetFileInfoNodeRed(node->mParent->mParent);
          FileInfoMapRotateLeft(map, node->mParent->mParent);
        }
      }
    }

    moho::FWHSFileInfoMapNode* const root = FileInfoMapRoot(map);
    SetFileInfoNodeBlack(root);
    if (!IsFileInfoMapSentinel(root)) {
      root->mParent = FileInfoMapHead(map);
    }
  }

  /**
   * Address: 0x0045DE90 (FUN_0045DE90, sub_45DE90)
   *
   * What it does:
   * Returns the left-most descendant from one file-info tree node.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoTreeMinimumFrom(moho::FWHSFileInfoMapNode* node)
  {
    while (!IsFileInfoMapSentinel(node) && !IsFileInfoMapSentinel(node->mLeft)) {
      node = node->mLeft;
    }
    return node;
  }

  /**
   * Address: 0x0045DE70 (FUN_0045DE70, sub_45DE70)
   *
   * What it does:
   * Returns the right-most descendant from one file-info tree node.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoTreeMaximumFrom(moho::FWHSFileInfoMapNode* node)
  {
    while (!IsFileInfoMapSentinel(node) && !IsFileInfoMapSentinel(node->mRight)) {
      node = node->mRight;
    }
    return node;
  }

  /**
   * Address: 0x0045E3A0 (FUN_0045E3A0, sub_45E3A0)
   *
   * What it does:
   * Moves one file-info iterator node to its in-order successor.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoTreeNextNode(
    moho::FWHSFileInfoMapNode* node, moho::FWHSFileInfoMapNode* const head
  )
  {
    if (IsFileInfoMapSentinel(node)) {
      return head;
    }

    if (!IsFileInfoMapSentinel(node->mRight)) {
      return FileInfoTreeMinimumFrom(node->mRight);
    }

    moho::FWHSFileInfoMapNode* parent = node->mParent;
    while (!IsFileInfoMapSentinel(parent) && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  /**
   * Address: 0x0045E340 (FUN_0045E340, sub_45E340)
   *
   * What it does:
   * Moves one file-info iterator node to its in-order predecessor.
   */
  [[nodiscard]]
  [[maybe_unused]]
  moho::FWHSFileInfoMapNode* FileInfoTreePreviousNode(
    moho::FWHSFileInfoMapNode* node, moho::FWHSFileInfoMapNode* const head
  )
  {
    if (IsFileInfoMapSentinel(node)) {
      return head->mRight;
    }

    if (!IsFileInfoMapSentinel(node->mLeft)) {
      return FileInfoTreeMaximumFrom(node->mLeft);
    }

    moho::FWHSFileInfoMapNode* parent = node->mParent;
    while (!IsFileInfoMapSentinel(parent) && node == parent->mLeft) {
      node = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  /**
   * Address: 0x0045DF10 (FUN_0045DF10, std::map_string_SDiskFileInfo::upper_bound)
   *
   * What it does:
   * Returns the first file-info node whose key is greater than the canonical
   * path.
   */
  [[nodiscard]]
  moho::FWHSFileInfoMapNode* FileInfoUpperBound(
    const moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map,
    const msvc8::string& canonicalPath
  )
  {
    moho::FWHSFileInfoMapNode* result = map.mHead;
    if (result == nullptr) {
      return nullptr;
    }

    moho::FWHSFileInfoMapNode* parent = result->mParent;
    while (!IsFileInfoMapSentinel(parent)) {
      if (CompareCanonicalPaths(canonicalPath, parent->mCanonicalPath) < 0) {
        result = parent;
        parent = parent->mLeft;
      } else {
        parent = parent->mRight;
      }
    }
    return result;
  }

  /**
   * Address: 0x0045AFE0 (FUN_0045AFE0, std::map_string_SDiskFileInfo::operator[])
   *
   * What it does:
   * Finds or creates one file-info cache record for the canonical path and
   * returns a typed reference to the value payload.
   */
  [[nodiscard]]
  moho::SDiskFileInfo* FileInfoMapGetOrCreate(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, const msvc8::string& canonicalPath
  )
  {
    EnsureFileInfoMapInitialized(map);
    moho::FWHSFileInfoMapNode* const head = map.mHead;
    if (head == nullptr) {
      return nullptr;
    }

    moho::FWHSFileInfoMapNode* const lowerBound = FileInfoLowerBound(map, canonicalPath);
    if (lowerBound != nullptr && lowerBound != head &&
        CompareCanonicalPaths(canonicalPath, lowerBound->mCanonicalPath) >= 0) {
      return &lowerBound->mInfo;
    }

    std::unique_ptr<moho::FWHSFileInfoMapNode> insertedNodeOwner =
      CreateFileInfoMapNode(head, head, head, canonicalPath, moho::SDiskFileInfo{});
    moho::FWHSFileInfoMapNode* const insertedNode = insertedNodeOwner.get();
    if (insertedNode == nullptr) {
      return nullptr;
    }

    moho::FWHSFileInfoMapNode* parent = head;
    moho::FWHSFileInfoMapNode* node = head->mParent;
    bool insertAsLeftChild = true;
    while (!IsFileInfoMapSentinel(node)) {
      parent = node;
      if (CompareCanonicalPaths(canonicalPath, node->mCanonicalPath) < 0) {
        node = node->mLeft;
        insertAsLeftChild = true;
      } else {
        node = node->mRight;
        insertAsLeftChild = false;
      }
    }

    insertedNode->mParent = parent;
    if (parent == head) {
      head->mParent = insertedNode;
      head->mLeft = insertedNode;
      head->mRight = insertedNode;
      insertedNode->mParent = head;
    } else if (insertAsLeftChild) {
      parent->mLeft = insertedNode;
      if (head->mLeft == parent ||
          CompareCanonicalPaths(insertedNode->mCanonicalPath, head->mLeft->mCanonicalPath) < 0) {
        head->mLeft = insertedNode;
      }
    } else {
      parent->mRight = insertedNode;
      if (head->mRight == parent ||
          CompareCanonicalPaths(insertedNode->mCanonicalPath, head->mRight->mCanonicalPath) > 0) {
        head->mRight = insertedNode;
      }
    }

    ++map.mSize;
    insertedNodeOwner.release();
    FileInfoMapInsertFixup(map, insertedNode);
    return &insertedNode->mInfo;
  }

  void FileInfoMapTransplant(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map,
    moho::FWHSFileInfoMapNode* const currentNode,
    moho::FWHSFileInfoMapNode* const replacementNode
  )
  {
    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    if (IsFileInfoMapSentinel(currentNode->mParent)) {
      head->mParent = IsFileInfoMapSentinel(replacementNode) ? head : replacementNode;
    } else if (currentNode == currentNode->mParent->mLeft) {
      currentNode->mParent->mLeft = replacementNode;
    } else {
      currentNode->mParent->mRight = replacementNode;
    }

    if (!IsFileInfoMapSentinel(replacementNode)) {
      replacementNode->mParent = currentNode->mParent;
    }
  }

  void FileInfoMapRebuildHeadLinks(moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map)
  {
    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    if (IsFileInfoMapSentinel(head)) {
      return;
    }

    moho::FWHSFileInfoMapNode* root = head->mParent;
    if (IsFileInfoMapSentinel(root)) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    head->mParent = root;
    root->mParent = head;
    head->mLeft = FileInfoTreeMinimumFrom(root);
    head->mRight = FileInfoTreeMaximumFrom(root);
  }

  void FileInfoMapDeleteFixup(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map,
    moho::FWHSFileInfoMapNode* node,
    moho::FWHSFileInfoMapNode* parent
  )
  {
    while (node != FileInfoMapRoot(map) && IsFileInfoNodeBlack(node)) {
      if (!IsFileInfoMapSentinel(parent) && node == parent->mLeft) {
        moho::FWHSFileInfoMapNode* sibling = parent->mRight;
        if (IsFileInfoNodeRed(sibling)) {
          SetFileInfoNodeBlack(sibling);
          SetFileInfoNodeRed(parent);
          FileInfoMapRotateLeft(map, parent);
          sibling = parent->mRight;
        }

        if (IsFileInfoMapSentinel(sibling) ||
            (IsFileInfoNodeBlack(sibling->mLeft) && IsFileInfoNodeBlack(sibling->mRight))) {
          SetFileInfoNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsFileInfoNodeBlack(sibling->mRight)) {
          SetFileInfoNodeBlack(sibling->mLeft);
          SetFileInfoNodeRed(sibling);
          FileInfoMapRotateRight(map, sibling);
          sibling = parent->mRight;
        }

        SetFileInfoNodeColor(sibling, parent->mColor);
        SetFileInfoNodeBlack(parent);
        SetFileInfoNodeBlack(sibling->mRight);
        FileInfoMapRotateLeft(map, parent);
        node = FileInfoMapRoot(map);
        parent = FileInfoMapHead(map);
      } else {
        moho::FWHSFileInfoMapNode* sibling = IsFileInfoMapSentinel(parent) ? FileInfoMapHead(map) : parent->mLeft;
        if (IsFileInfoNodeRed(sibling)) {
          SetFileInfoNodeBlack(sibling);
          SetFileInfoNodeRed(parent);
          FileInfoMapRotateRight(map, parent);
          sibling = parent->mLeft;
        }

        if (IsFileInfoMapSentinel(sibling) ||
            (IsFileInfoNodeBlack(sibling->mRight) && IsFileInfoNodeBlack(sibling->mLeft))) {
          SetFileInfoNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsFileInfoNodeBlack(sibling->mLeft)) {
          SetFileInfoNodeBlack(sibling->mRight);
          SetFileInfoNodeRed(sibling);
          FileInfoMapRotateLeft(map, sibling);
          sibling = parent->mLeft;
        }

        SetFileInfoNodeColor(sibling, parent->mColor);
        SetFileInfoNodeBlack(parent);
        SetFileInfoNodeBlack(sibling->mLeft);
        FileInfoMapRotateRight(map, parent);
        node = FileInfoMapRoot(map);
        parent = FileInfoMapHead(map);
      }
    }

    SetFileInfoNodeBlack(node);
  }

  /**
   * Address: 0x0045CB80 (FUN_0045CB80, sub_45CB80)
   *
   * What it does:
   * Erases one file-info map node by iterator and rebalances sentinel links.
   */
  void FileInfoMapEraseNode(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, moho::FWHSFileInfoMapNode* const nodeToErase
  )
  {
    if (IsFileInfoMapSentinel(nodeToErase)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    moho::FWHSFileInfoMapNode* removedNode = nodeToErase;
    moho::FWHSFileInfoMapNode* fixupNode = FileInfoMapHead(map);
    moho::FWHSFileInfoMapNode* fixupParent = FileInfoMapHead(map);
    bool removedNodeWasBlack = IsFileInfoNodeBlack(removedNode);

    if (IsFileInfoMapSentinel(nodeToErase->mLeft)) {
      fixupNode = nodeToErase->mRight;
      fixupParent = nodeToErase->mParent;
      FileInfoMapTransplant(map, nodeToErase, nodeToErase->mRight);
    } else if (IsFileInfoMapSentinel(nodeToErase->mRight)) {
      fixupNode = nodeToErase->mLeft;
      fixupParent = nodeToErase->mParent;
      FileInfoMapTransplant(map, nodeToErase, nodeToErase->mLeft);
    } else {
      removedNode = FileInfoTreeMinimumFrom(nodeToErase->mRight);
      removedNodeWasBlack = IsFileInfoNodeBlack(removedNode);
      fixupNode = removedNode->mRight;

      if (removedNode->mParent == nodeToErase) {
        fixupParent = removedNode;
      } else {
        fixupParent = removedNode->mParent;
        FileInfoMapTransplant(map, removedNode, removedNode->mRight);
        removedNode->mRight = nodeToErase->mRight;
        removedNode->mRight->mParent = removedNode;
      }

      FileInfoMapTransplant(map, nodeToErase, removedNode);
      removedNode->mLeft = nodeToErase->mLeft;
      removedNode->mLeft->mParent = removedNode;
      removedNode->mColor = nodeToErase->mColor;
    }

    if (removedNodeWasBlack) {
      FileInfoMapDeleteFixup(map, fixupNode, fixupParent);
    }

    ResetLegacyStringStorage(nodeToErase->mCanonicalPath);
    delete nodeToErase;
    if (map.mSize != 0) {
      --map.mSize;
    }
    FileInfoMapRebuildHeadLinks(map);
  }

  /**
   * Address: 0x0045B100 (FUN_0045B100, std::map_string_SDiskFileInfo::erase)
   *
   * What it does:
   * Removes file-info cache nodes for one canonical key and returns the number
   * of erased nodes.
   */
  [[nodiscard]]
  std::uint32_t FileInfoMapRemoveByCanonicalPath(
    moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map, const msvc8::string& canonicalPath
  )
  {
    moho::FWHSFileInfoMapNode* const head = FileInfoMapHead(map);
    if (IsFileInfoMapSentinel(head)) {
      return 0;
    }

    moho::FWHSFileInfoMapNode* first = FileInfoLowerBound(map, canonicalPath);
    moho::FWHSFileInfoMapNode* const last = FileInfoUpperBound(map, canonicalPath);
    std::uint32_t removedCount = 0;

    while (!IsFileInfoMapSentinel(first) && first != last) {
      moho::FWHSFileInfoMapNode* const next = FileInfoTreeNextNode(first, head);
      FileInfoMapEraseNode(map, first);
      first = next;
      ++removedCount;
    }

    return removedCount;
  }

  [[nodiscard]]
  bool HasWriteTime(const moho::SDiskFileInfo& info)
  {
    return info.mLastWriteTime.dwLowDateTime != 0 || info.mLastWriteTime.dwHighDateTime != 0;
  }

  [[nodiscard]]
  moho::EFileAttributes BuildFileAttributesFromWin32(const DWORD win32Attributes)
  {
    const std::uint32_t readonlyFlag = (win32Attributes & FILE_ATTRIBUTE_READONLY) != 0 ? moho::FA_Readonly : 0u;
    const std::uint32_t directoryFlag = (win32Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? moho::FA_Directory : 0u;
    return static_cast<moho::EFileAttributes>(readonlyFlag | directoryFlag);
  }

  [[nodiscard]]
  bool TryQueryFileAttributes(const msvc8::string& canonicalPath, moho::SDiskFileInfo* const outInfo)
  {
    const std::wstring sourcePathWide = gpg::STR_Utf8ToWide(canonicalPath.c_str());
    WIN32_FILE_ATTRIBUTE_DATA fileInfo{};
    if (::GetFileAttributesExW(sourcePathWide.c_str(), GetFileExInfoStandard, &fileInfo) == FALSE) {
      if (outInfo != nullptr) {
        outInfo->mFileAttributes = moho::FA_None;
        outInfo->mFileSize = 0;
        outInfo->mLastWriteTime = FILETIME{};
      }
      return false;
    }

    if (outInfo != nullptr) {
      outInfo->mFileAttributes = BuildFileAttributesFromWin32(fileInfo.dwFileAttributes);
      outInfo->mFileSize = fileInfo.nFileSizeLow;
      outInfo->mLastWriteTime = fileInfo.ftLastWriteTime;
    }
    return true;
  }

  void AddWaitHandleReference(moho::SFileWaitHandle* const handle)
  {
    if (handle != nullptr) {
      (void)::InterlockedExchangeAdd(&handle->mLock, 1);
    }
  }

  void ReleaseWaitHandleReference(moho::SFileWaitHandle* const handle)
  {
    if (handle == nullptr) {
      return;
    }

    if (::InterlockedExchangeAdd(&handle->mLock, -1) == 1) {
      moho::FILE_EnsureWaitHandleSet();
      if (sPFWaitHandleSet != nullptr) {
        sPFWaitHandleSet->RemoveEntry(handle);
      }
    }
  }

  void UnmapFileView(const char* const mappedView)
  {
    if (mappedView != nullptr) {
      (void)::UnmapViewOfFile(mappedView);
    }
  }

  void SetWaitHandleErrorString(moho::FWaitHandleSet* const waitHandleSet, const msvc8::string& errorText)
  {
    if (waitHandleSet == nullptr) {
      return;
    }

    if (msvc8::string* const errorSlot = waitHandleSet->ErrorString(); errorSlot != nullptr) {
      errorSlot->assign_owned(errorText.view());
    }
  }

  void SetWaitHandleErrorFromWin32(moho::FWaitHandleSet* const waitHandleSet)
  {
    SetWaitHandleErrorString(waitHandleSet, moho::WIN_GetLastError());
  }

  class ScopedWaitNotify
  {
  public:
    /**
     * Address: 0x00457CA0 (FUN_00457CA0, ScopedWaitNotify::ScopedWaitNotify)
     *
     * What it does:
     * Acquires one shared wait lane and arms deferred notify-on-scope-exit.
     */
    explicit ScopedWaitNotify(moho::FWaitHandleSet& waitHandleSet)
      : mWaitHandleSet(waitHandleSet)
    {
      mWaitHandleSet.Wait();
    }

    ~ScopedWaitNotify()
    {
      if (mShouldNotify) {
        mWaitHandleSet.Notify();
      }
    }

    /**
     * Address: 0x00457CB0 (FUN_00457CB0, ScopedWaitNotify::NotifyNow)
     *
     * What it does:
     * Emits one deferred shared-lane notify exactly once for the owning
     * wait-handle set.
     */
    void NotifyNow()
    {
      if (mShouldNotify) {
        mWaitHandleSet.Notify();
        mShouldNotify = false;
      }
    }

  private:
    moho::FWaitHandleSet& mWaitHandleSet;
    bool mShouldNotify = true;
  };

  class ScopedHandleRef
  {
  public:
    explicit ScopedHandleRef(moho::SFileWaitHandle* const handle)
      : mHandle(handle)
    {
      AddWaitHandleReference(mHandle);
    }

    ~ScopedHandleRef()
    {
      ReleaseWaitHandleReference(mHandle);
    }

  private:
    moho::SFileWaitHandle* mHandle = nullptr;
  };

  /**
   * Address: 0x00459100 (FUN_00459100, func_OpenFileRead)
   *
   * Moho::FWaitHandleSet &,gpg::StrArg
   *
   * What it does:
   * Opens one canonicalized path from the mounted zip-entry map when present;
   * otherwise opens a plain file stream from disk.
   */
  [[nodiscard]]
  msvc8::auto_ptr<gpg::Stream> OpenFileReadFromWaitHandleSet(
    moho::FWaitHandleSet& waitHandleSet, const gpg::StrArg sourcePath
  )
  {
    msvc8::string canonicalPath{};
    gpg::STR_CanonizeFilename(&canonicalPath, sourcePath != nullptr ? sourcePath : "");

    ScopedWaitNotify notifyGuard(waitHandleSet);

    moho::FWHSZipEntryMapNode* const zipNode = ZipEntryFind(waitHandleSet.mZipEntries, canonicalPath);
    if (zipNode != nullptr && zipNode != waitHandleSet.mZipEntries.mHead) {
      moho::SFileWaitHandle* const handle = zipNode->mEntry.mHandle;
      const std::uint32_t zipEntryIndex = zipNode->mEntry.mZipEntryIndex;
      ScopedHandleRef handleRef(handle);
      notifyGuard.NotifyNow();

      if (handle == nullptr || handle->mZipFile == nullptr) {
        return msvc8::auto_ptr<gpg::Stream>(nullptr);
      }

      return handle->mZipFile->OpenEntry(zipEntryIndex);
    }

    return msvc8::auto_ptr<gpg::Stream>(
      new gpg::FileStream(canonicalPath.c_str(), gpg::Stream::ModeReceive, 0x0Bu, 4096)
    );
  }

  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipMapHead(const moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map)
  {
    return map.mHead;
  }

  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipMapRoot(const moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map)
  {
    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    if (IsZipMapSentinel(head)) {
      return head;
    }
    return head->mParent;
  }

  [[nodiscard]]
  bool IsZipNodeBlack(const moho::FWHSZipEntryMapNode* const node)
  {
    return IsZipMapSentinel(node) || node->mColor != 0;
  }

  [[nodiscard]]
  bool IsZipNodeRed(const moho::FWHSZipEntryMapNode* const node)
  {
    return !IsZipNodeBlack(node);
  }

  void SetZipNodeBlack(moho::FWHSZipEntryMapNode* const node)
  {
    if (!IsZipMapSentinel(node)) {
      node->mColor = 1;
    }
  }

  void SetZipNodeRed(moho::FWHSZipEntryMapNode* const node)
  {
    if (!IsZipMapSentinel(node)) {
      node->mColor = 0;
    }
  }

  void SetZipNodeColor(moho::FWHSZipEntryMapNode* const node, const std::uint8_t color)
  {
    if (!IsZipMapSentinel(node)) {
      node->mColor = color;
    }
  }

  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipTreeMinimumFrom(moho::FWHSZipEntryMapNode* node)
  {
    while (!IsZipMapSentinel(node) && !IsZipMapSentinel(node->mLeft)) {
      node = node->mLeft;
    }
    return node;
  }

  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipTreeMaximumFrom(moho::FWHSZipEntryMapNode* node)
  {
    while (!IsZipMapSentinel(node) && !IsZipMapSentinel(node->mRight)) {
      node = node->mRight;
    }
    return node;
  }

  /**
   * Address: 0x0045E080 (FUN_0045E080, sub_45E080)
   *
   * What it does:
   * Moves one zip-map iterator node to its in-order predecessor.
   */
  [[nodiscard]]
  [[maybe_unused]]
  moho::FWHSZipEntryMapNode* ZipTreePreviousNode(
    moho::FWHSZipEntryMapNode* node, moho::FWHSZipEntryMapNode* const head
  )
  {
    if (IsZipMapSentinel(node)) {
      return head->mRight;
    }

    if (!IsZipMapSentinel(node->mLeft)) {
      return ZipTreeMaximumFrom(node->mLeft);
    }

    moho::FWHSZipEntryMapNode* parent = node->mParent;
    while (!IsZipMapSentinel(parent) && node == parent->mLeft) {
      node = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  /**
   * Address: 0x0045D170 (FUN_0045D170, std::map_string_FWHSEntry::Iterator::inc)
   *
   * What it does:
   * Advances one zip-map node iterator to its in-order successor.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipTreeNextNode(
    moho::FWHSZipEntryMapNode* node, moho::FWHSZipEntryMapNode* const head
  )
  {
    if (IsZipMapSentinel(node)) {
      return head;
    }

    if (!IsZipMapSentinel(node->mRight)) {
      return ZipTreeMinimumFrom(node->mRight);
    }

    moho::FWHSZipEntryMapNode* parent = node->mParent;
    while (!IsZipMapSentinel(parent) && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }
    return parent;
  }

  /**
   * Address: 0x0045E1B0 (FUN_0045E1B0, sub_45E1B0)
   *
   * What it does:
   * Initializes one zip-entry map node payload and tree links.
   */
  moho::FWHSZipEntryMapNode* InitializeZipEntryMapNode(
    moho::FWHSZipEntryMapNode* const left,
    moho::FWHSZipEntryMapNode* const right,
    moho::FWHSZipEntryMapNode* const parent,
    moho::FWHSZipEntryMapNode* const node,
    const msvc8::string& canonicalPath,
    const moho::FWHSEntry& entry
  )
  {
    node->mParent = parent;
    node->mLeft = left;
    node->mRight = right;
    node->mCanonicalPath.assign_owned(canonicalPath.view());
    node->mEntry = entry;
    node->mColor = 0;
    node->mIsNil = 0;
    return node;
  }

  /**
   * Address context:
   * - 0x0045E1B0 (FUN_0045E1B0, sub_45E1B0) shared node initializer lane.
   * - 0x0045C940 (FUN_0045C940, sub_45C940) allocator wrapper.
   *
   * What it does:
   * Allocates and initializes one zip-entry map node for insertion.
   */
  [[nodiscard]]
  std::unique_ptr<moho::FWHSZipEntryMapNode> CreateZipEntryNode(
    moho::FWHSZipEntryMapNode* const head,
    const msvc8::string& canonicalPath,
    moho::SFileWaitHandle* const handle,
    const std::uint32_t zipEntryIndex
  )
  {
    moho::FWHSZipEntryMapNode* const insertedNode = ::new (AllocateZipEntryMapNodes(1u)) moho::FWHSZipEntryMapNode();
    std::unique_ptr<moho::FWHSZipEntryMapNode> insertedNodeOwner(insertedNode);
    const moho::FWHSEntry entry{handle, zipEntryIndex};
    (void)InitializeZipEntryMapNode(head, head, head, insertedNodeOwner.get(), canonicalPath, entry);
    return insertedNodeOwner;
  }

  void ZipMapRotateLeft(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map, moho::FWHSZipEntryMapNode* const pivot
  )
  {
    if (IsZipMapSentinel(pivot) || IsZipMapSentinel(pivot->mRight)) {
      return;
    }

    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    moho::FWHSZipEntryMapNode* const right = pivot->mRight;

    pivot->mRight = right->mLeft;
    if (!IsZipMapSentinel(right->mLeft)) {
      right->mLeft->mParent = pivot;
    }

    right->mParent = pivot->mParent;
    if (IsZipMapSentinel(pivot->mParent)) {
      head->mParent = right;
    } else if (pivot == pivot->mParent->mLeft) {
      pivot->mParent->mLeft = right;
    } else {
      pivot->mParent->mRight = right;
    }

    right->mLeft = pivot;
    pivot->mParent = right;
  }

  void ZipMapRotateRight(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map, moho::FWHSZipEntryMapNode* const pivot
  )
  {
    if (IsZipMapSentinel(pivot) || IsZipMapSentinel(pivot->mLeft)) {
      return;
    }

    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    moho::FWHSZipEntryMapNode* const left = pivot->mLeft;

    pivot->mLeft = left->mRight;
    if (!IsZipMapSentinel(left->mRight)) {
      left->mRight->mParent = pivot;
    }

    left->mParent = pivot->mParent;
    if (IsZipMapSentinel(pivot->mParent)) {
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
   * Address: 0x0045DD20 (FUN_0045DD20, sub_45DD20)
   *
   * What it does:
   * Allocates and initializes one zip-entry map head/sentinel node.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* CreateZipMapHeadNode()
  {
    moho::FWHSZipEntryMapNode* const head = ::new (AllocateZipEntryMapNodes(1u)) moho::FWHSZipEntryMapNode();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mColor = 1;
    head->mIsNil = 1;
    return head;
  }

  void EnsureZipMapInitialized(moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map)
  {
    if (map.mHead != nullptr) {
      return;
    }

    map.mHead = CreateZipMapHeadNode();
    map.mSize = 0;
  }

  void ZipMapInsertFixup(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map, moho::FWHSZipEntryMapNode* node
  )
  {
    while (!IsZipMapSentinel(node->mParent) && node->mParent->mColor == 0) {
      moho::FWHSZipEntryMapNode* const parent = node->mParent;
      moho::FWHSZipEntryMapNode* const grandparent = parent->mParent;
      if (parent == grandparent->mLeft) {
        moho::FWHSZipEntryMapNode* uncle = grandparent->mRight;
        if (!IsZipMapSentinel(uncle) && uncle->mColor == 0) {
          SetZipNodeBlack(parent);
          SetZipNodeBlack(uncle);
          SetZipNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mRight) {
            node = parent;
            ZipMapRotateLeft(map, node);
          }
          SetZipNodeBlack(node->mParent);
          SetZipNodeRed(node->mParent->mParent);
          ZipMapRotateRight(map, node->mParent->mParent);
        }
      } else {
        moho::FWHSZipEntryMapNode* uncle = grandparent->mLeft;
        if (!IsZipMapSentinel(uncle) && uncle->mColor == 0) {
          SetZipNodeBlack(parent);
          SetZipNodeBlack(uncle);
          SetZipNodeRed(grandparent);
          node = grandparent;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            ZipMapRotateRight(map, node);
          }
          SetZipNodeBlack(node->mParent);
          SetZipNodeRed(node->mParent->mParent);
          ZipMapRotateLeft(map, node->mParent->mParent);
        }
      }
    }

    moho::FWHSZipEntryMapNode* const root = ZipMapRoot(map);
    SetZipNodeBlack(root);
    if (!IsZipMapSentinel(root)) {
      root->mParent = ZipMapHead(map);
    }
  }

  /**
   * Address: 0x0045AB60 (FUN_0045AB60, sub_45AB60)
   *
   * What it does:
   * Inserts one canonical mounted-file key into the zip-entry red-black map
   * when not already present.
   */
  bool ZipMapInsertUniqueEntry(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    const msvc8::string& canonicalPath,
    moho::SFileWaitHandle* const handle,
    const std::uint32_t zipEntryIndex
  )
  {
    EnsureZipMapInitialized(map);
    moho::FWHSZipEntryMapNode* const head = map.mHead;
    if (head == nullptr) {
      return false;
    }

    moho::FWHSZipEntryMapNode* const lowerBound = ZipEntryLowerBound(map, canonicalPath);
    if (lowerBound != nullptr && lowerBound != head &&
        CompareCanonicalPaths(canonicalPath, lowerBound->mCanonicalPath) >= 0) {
      return false;
    }

    std::unique_ptr<moho::FWHSZipEntryMapNode> insertedNodeOwner =
      CreateZipEntryNode(head, canonicalPath, handle, zipEntryIndex);
    moho::FWHSZipEntryMapNode* const insertedNode = insertedNodeOwner.get();

    moho::FWHSZipEntryMapNode* parent = head;
    moho::FWHSZipEntryMapNode* node = head->mParent;
    bool insertAsLeftChild = true;
    while (!IsZipMapSentinel(node)) {
      parent = node;
      if (CompareCanonicalPaths(canonicalPath, node->mCanonicalPath) < 0) {
        node = node->mLeft;
        insertAsLeftChild = true;
      } else {
        node = node->mRight;
        insertAsLeftChild = false;
      }
    }

    insertedNode->mParent = parent;
    if (parent == head) {
      head->mParent = insertedNode;
      head->mLeft = insertedNode;
      head->mRight = insertedNode;
      insertedNode->mParent = head;
    } else if (insertAsLeftChild) {
      parent->mLeft = insertedNode;
      if (head->mLeft == parent ||
          CompareCanonicalPaths(insertedNode->mCanonicalPath, head->mLeft->mCanonicalPath) < 0) {
        head->mLeft = insertedNode;
      }
    } else {
      parent->mRight = insertedNode;
      if (head->mRight == parent ||
          CompareCanonicalPaths(insertedNode->mCanonicalPath, head->mRight->mCanonicalPath) > 0) {
        head->mRight = insertedNode;
      }
    }

    ++map.mSize;
    insertedNodeOwner.release();
    ZipMapInsertFixup(map, insertedNode);
    return true;
  }

  void ZipMapTransplant(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    moho::FWHSZipEntryMapNode* const currentNode,
    moho::FWHSZipEntryMapNode* const replacementNode
  )
  {
    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    if (IsZipMapSentinel(currentNode->mParent)) {
      head->mParent = IsZipMapSentinel(replacementNode) ? head : replacementNode;
    } else if (currentNode == currentNode->mParent->mLeft) {
      currentNode->mParent->mLeft = replacementNode;
    } else {
      currentNode->mParent->mRight = replacementNode;
    }

    if (!IsZipMapSentinel(replacementNode)) {
      replacementNode->mParent = currentNode->mParent;
    }
  }

  void ZipMapRebuildHeadLinks(moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map)
  {
    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    if (IsZipMapSentinel(head)) {
      return;
    }

    moho::FWHSZipEntryMapNode* root = head->mParent;
    if (IsZipMapSentinel(root)) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    head->mParent = root;
    root->mParent = head;
    head->mLeft = ZipTreeMinimumFrom(root);
    head->mRight = ZipTreeMaximumFrom(root);
  }

  void ZipMapDeleteFixup(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    moho::FWHSZipEntryMapNode* node,
    moho::FWHSZipEntryMapNode* parent
  )
  {
    while (node != ZipMapRoot(map) && IsZipNodeBlack(node)) {
      if (!IsZipMapSentinel(parent) && node == parent->mLeft) {
        moho::FWHSZipEntryMapNode* sibling = parent->mRight;
        if (IsZipNodeRed(sibling)) {
          SetZipNodeBlack(sibling);
          SetZipNodeRed(parent);
          ZipMapRotateLeft(map, parent);
          sibling = parent->mRight;
        }

        if (IsZipMapSentinel(sibling) || (IsZipNodeBlack(sibling->mLeft) && IsZipNodeBlack(sibling->mRight))) {
          SetZipNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsZipNodeBlack(sibling->mRight)) {
          SetZipNodeBlack(sibling->mLeft);
          SetZipNodeRed(sibling);
          ZipMapRotateRight(map, sibling);
          sibling = parent->mRight;
        }

        SetZipNodeColor(sibling, parent->mColor);
        SetZipNodeBlack(parent);
        SetZipNodeBlack(sibling->mRight);
        ZipMapRotateLeft(map, parent);
        node = ZipMapRoot(map);
        parent = ZipMapHead(map);
      } else {
        moho::FWHSZipEntryMapNode* sibling = IsZipMapSentinel(parent) ? ZipMapHead(map) : parent->mLeft;
        if (IsZipNodeRed(sibling)) {
          SetZipNodeBlack(sibling);
          SetZipNodeRed(parent);
          ZipMapRotateRight(map, parent);
          sibling = parent->mLeft;
        }

        if (IsZipMapSentinel(sibling) || (IsZipNodeBlack(sibling->mRight) && IsZipNodeBlack(sibling->mLeft))) {
          SetZipNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsZipNodeBlack(sibling->mLeft)) {
          SetZipNodeBlack(sibling->mRight);
          SetZipNodeRed(sibling);
          ZipMapRotateLeft(map, sibling);
          sibling = parent->mLeft;
        }

        SetZipNodeColor(sibling, parent->mColor);
        SetZipNodeBlack(parent);
        SetZipNodeBlack(sibling->mLeft);
        ZipMapRotateRight(map, parent);
        node = ZipMapRoot(map);
        parent = ZipMapHead(map);
      }
    }

    SetZipNodeBlack(node);
  }

  /**
   * Address: 0x0045AC70 (FUN_0045AC70, std::map_string_FWHSEntry::remove)
   *
   * What it does:
   * Erases one zip-entry node from the intrusive red-black map and updates
   * sentinel head links.
   */
  void ZipMapEraseNode(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map, moho::FWHSZipEntryMapNode* const nodeToErase
  )
  {
    if (IsZipMapSentinel(nodeToErase)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    moho::FWHSZipEntryMapNode* removedNode = nodeToErase;
    moho::FWHSZipEntryMapNode* fixupNode = ZipMapHead(map);
    moho::FWHSZipEntryMapNode* fixupParent = ZipMapHead(map);
    bool removedNodeWasBlack = IsZipNodeBlack(removedNode);

    if (IsZipMapSentinel(nodeToErase->mLeft)) {
      fixupNode = nodeToErase->mRight;
      fixupParent = nodeToErase->mParent;
      ZipMapTransplant(map, nodeToErase, nodeToErase->mRight);
    } else if (IsZipMapSentinel(nodeToErase->mRight)) {
      fixupNode = nodeToErase->mLeft;
      fixupParent = nodeToErase->mParent;
      ZipMapTransplant(map, nodeToErase, nodeToErase->mLeft);
    } else {
      removedNode = ZipTreeMinimumFrom(nodeToErase->mRight);
      removedNodeWasBlack = IsZipNodeBlack(removedNode);
      fixupNode = removedNode->mRight;

      if (removedNode->mParent == nodeToErase) {
        fixupParent = removedNode;
      } else {
        fixupParent = removedNode->mParent;
        ZipMapTransplant(map, removedNode, removedNode->mRight);
        removedNode->mRight = nodeToErase->mRight;
        removedNode->mRight->mParent = removedNode;
      }

      ZipMapTransplant(map, nodeToErase, removedNode);
      removedNode->mLeft = nodeToErase->mLeft;
      removedNode->mLeft->mParent = removedNode;
      removedNode->mColor = nodeToErase->mColor;
    }

    if (removedNodeWasBlack) {
      ZipMapDeleteFixup(map, fixupNode, fixupParent);
    }

    ResetLegacyStringStorage(nodeToErase->mCanonicalPath);
    delete nodeToErase;
    if (map.mSize != 0) {
      --map.mSize;
    }
    ZipMapRebuildHeadLinks(map);
  }

  /**
   * Address: 0x0045E280 (FUN_0045E280, sub_45E280)
   *
   * What it does:
   * Recursively destroys one zip-entry map subtree and canonical-path storage.
   */
  void DestroyZipSubtreeNodes(
    moho::FWHSZipEntryMapNode* const node, const moho::FWHSZipEntryMapNode* const head
  )
  {
    moho::FWHSZipEntryMapNode* current = node;
    while (current != nullptr && current != head && current->mIsNil == 0) {
      DestroyZipSubtreeNodes(current->mRight, head);
      moho::FWHSZipEntryMapNode* const left = current->mLeft;
      ResetLegacyStringStorage(current->mCanonicalPath);
      delete current;
      current = left;
    }
  }

  /**
   * Address: 0x0045C800 (FUN_0045C800, sub_45C800)
   *
   * What it does:
   * Erases one half-open zip-map iterator range `[first, last)` and returns
   * the first iterator not erased.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMapNode* ZipMapEraseRange(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map,
    moho::FWHSZipEntryMapNode* first,
    moho::FWHSZipEntryMapNode* const last
  )
  {
    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    if (head != nullptr && first == head->mLeft && last == head) {
      DestroyZipSubtreeNodes(head->mParent, head);
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      map.mSize = 0;
      return head->mLeft;
    }

    while (!IsZipMapSentinel(first) && first != last) {
      moho::FWHSZipEntryMapNode* const next = ZipTreeNextNode(first, head);
      ZipMapEraseNode(map, first);
      first = next;
    }
    return first;
  }

  [[nodiscard]]
  moho::FWHSZipEntryMapNode* FindZipNodeByHandle(
    moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map, const moho::SFileWaitHandle* const handle
  )
  {
    moho::FWHSZipEntryMapNode* const head = ZipMapHead(map);
    moho::FWHSZipEntryMapNode* node = ZipTreeMinimumFrom(ZipMapRoot(map));
    while (!IsZipMapSentinel(node)) {
      if (node->mEntry.mHandle == handle) {
        return node;
      }
      node = ZipTreeNextNode(node, head);
    }
    return head;
  }

  [[nodiscard]]
  moho::SFileWaitHandle* WaitHandleListSentinel(moho::FWaitHandleSet& waitHandleSet)
  {
    return reinterpret_cast<moho::SFileWaitHandle*>(&waitHandleSet.mPrev);
  }

  [[nodiscard]]
  moho::SFileWaitHandle* FindMountedZipHandleByCanonicalPath(
    moho::FWaitHandleSet& waitHandleSet, const msvc8::string& canonicalPath
  )
  {
    moho::SFileWaitHandle* const sentinel = WaitHandleListSentinel(waitHandleSet);
    for (moho::SFileWaitHandle* node = waitHandleSet.mNext; node != sentinel; node = node->mNext) {
      const moho::CZipFile* const zipFile = node != nullptr ? node->mZipFile : nullptr;
      if (zipFile != nullptr && CompareCanonicalPaths(zipFile->mPath, canonicalPath) == 0) {
        return node;
      }
    }
    return nullptr;
  }

  void LinkMountedZipHandle(moho::FWaitHandleSet& waitHandleSet, moho::SFileWaitHandle* const handle)
  {
    if (handle == nullptr) {
      return;
    }

    moho::SFileWaitHandle* const sentinel = WaitHandleListSentinel(waitHandleSet);
    handle->mPrev = sentinel->mPrev;
    handle->mNext = sentinel;
    sentinel->mPrev->mNext = handle;
    sentinel->mPrev = handle;
  }

  /**
   * Address: 0x004584B0 (FUN_004584B0, func_MountZipFile)
   *
   * gpg::StrArg
   *
   * What it does:
   * Canonicalizes one zip path, deduplicates mounted handles by archive path,
   * then inserts all non-directory zip entries into the mounted zip-entry map.
   */
  [[nodiscard]]
  moho::SFileWaitHandle* MountZipFile(moho::FWaitHandleSet& waitHandleSet, const gpg::StrArg sourcePath)
  {
    msvc8::string canonicalPath{};
    gpg::STR_CanonizeFilename(&canonicalPath, sourcePath != nullptr ? sourcePath : "");

    waitHandleSet.Lock();
    if (moho::SFileWaitHandle* const existingHandle =
          FindMountedZipHandleByCanonicalPath(waitHandleSet, canonicalPath);
        existingHandle != nullptr) {
      AddWaitHandleReference(existingHandle);
      waitHandleSet.NotifyAll();
      return existingHandle;
    }
    waitHandleSet.NotifyAll();

    std::unique_ptr<moho::CZipFile> mountedZip = std::make_unique<moho::CZipFile>(canonicalPath.c_str());
    if (mountedZip->mEntries.empty()) {
      return nullptr;
    }

    waitHandleSet.Lock();
    if (moho::SFileWaitHandle* const existingHandle =
          FindMountedZipHandleByCanonicalPath(waitHandleSet, canonicalPath);
        existingHandle != nullptr) {
      AddWaitHandleReference(existingHandle);
      waitHandleSet.NotifyAll();
      return existingHandle;
    }

    std::unique_ptr<moho::SFileWaitHandle> mountedHandle = std::make_unique<moho::SFileWaitHandle>();
    mountedHandle->mZipFile = mountedZip.release();
    mountedHandle->mLock = 1;

    msvc8::string mountedPathPrefix{};
    mountedPathPrefix.assign_owned(canonicalPath.view());
    if (mountedPathPrefix.empty() || mountedPathPrefix[mountedPathPrefix.size() - 1] != '\\') {
      (void)mountedPathPrefix.push_back('\\');
    }
    const std::size_t prefixSize = mountedPathPrefix.size();

    try {
      const std::size_t entryCount = mountedHandle->mZipFile->mEntries.size();
      for (std::size_t entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
        const msvc8::string loweredEntryName =
          gpg::STR_ToLower(mountedHandle->mZipFile->GetEntryName(static_cast<std::uint32_t>(entryIndex)).c_str());
        if (!loweredEntryName.empty() && loweredEntryName[loweredEntryName.size() - 1] == '/') {
          continue;
        }

        msvc8::string mountedEntryPath = mountedPathPrefix + loweredEntryName;
        for (std::size_t cursor = prefixSize; cursor < mountedEntryPath.size(); ++cursor) {
          if (mountedEntryPath[cursor] == '/') {
            mountedEntryPath[cursor] = '\\';
          }
        }

        (void)ZipMapInsertUniqueEntry(
          waitHandleSet.mZipEntries,
          mountedEntryPath,
          mountedHandle.get(),
          static_cast<std::uint32_t>(entryIndex)
        );
      }
    } catch (...) {
      while (true) {
        moho::FWHSZipEntryMapNode* const danglingNode =
          FindZipNodeByHandle(waitHandleSet.mZipEntries, mountedHandle.get());
        if (IsZipMapSentinel(danglingNode)) {
          break;
        }
        ZipMapEraseNode(waitHandleSet.mZipEntries, danglingNode);
      }
      delete mountedHandle->mZipFile;
      mountedHandle->mZipFile = nullptr;
      waitHandleSet.NotifyAll();
      return nullptr;
    }

    LinkMountedZipHandle(waitHandleSet, mountedHandle.get());
    waitHandleSet.NotifyAll();
    return mountedHandle.release();
  }

  void ReleaseWaitHandleSetVfs(moho::FWaitHandleSet& waitHandleSet)
  {
    moho::CVirtualFileSystem* const vfs = waitHandleSet.mHandle;
    waitHandleSet.mHandle = nullptr;
    if (vfs != nullptr) {
      delete vfs;
    }
  }

  /**
   * Address: 0x0045B290 (FUN_0045B290, boost::thread_specific_ptr::release)
   *
   * What it does:
   * Releases one current-thread disk-thread-state value lane and clears the
   * owning TSS slot descriptor.
   */
  void ReleaseWaitHandleThreadStateRuntime(moho::FWHSThreadStateRuntime& runtime)
  {
    CleanupDiskThreadStateValue(runtime);
    runtime.mTss = nullptr;
  }

  /**
   * Address: 0x0045DDB0 (FUN_0045DDB0, sub_45DDB0)
   *
   * What it does:
   * Recursively destroys one file-info map subtree, including per-node
   * canonical-path string storage.
   */
  void DestroyFileInfoSubtreeNodes(
    moho::FWHSFileInfoMapNode* const node, const moho::FWHSFileInfoMapNode* const head
  )
  {
    moho::FWHSFileInfoMapNode* current = node;
    while (current != nullptr && current != head && current->mIsNil == 0) {
      DestroyFileInfoSubtreeNodes(current->mRight, head);
      moho::FWHSFileInfoMapNode* const left = current->mLeft;
      ResetLegacyStringStorage(current->mCanonicalPath);
      delete current;
      current = left;
    }
  }

  void ClearFileInfoMapStorage(moho::FWHSTreeMap<moho::FWHSFileInfoMapNode>& map)
  {
    moho::FWHSFileInfoMapNode* const head = map.mHead;
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    DestroyFileInfoSubtreeNodes(head->mParent, head);
    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

  void ClearZipMapStorage(moho::FWHSTreeMap<moho::FWHSZipEntryMapNode>& map)
  {
    moho::FWHSZipEntryMapNode* const head = map.mHead;
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    (void)ZipMapEraseRange(map, ZipTreeMinimumFrom(ZipMapRoot(map)), head);

    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

  void UnlinkWaitHandleSetSentinel(moho::FWaitHandleSet& waitHandleSet)
  {
    if (waitHandleSet.mPrev != nullptr) {
      waitHandleSet.mPrev->mNext = waitHandleSet.mNext;
    }
    if (waitHandleSet.mNext != nullptr) {
      waitHandleSet.mNext->mPrev = waitHandleSet.mPrev;
    }

    moho::SFileWaitHandle* const sentinel = reinterpret_cast<moho::SFileWaitHandle*>(&waitHandleSet.mPrev);
    waitHandleSet.mPrev = sentinel;
    waitHandleSet.mNext = sentinel;
  }

  /**
   * Address: 0x00413EC0 (FUN_00413EC0, func_InitFileWaitHandleSet)
   *
   * What it does:
   * Initializes the static file wait-handle object runtime lanes before the
   * singleton publish step.
   */
  moho::FWaitHandleSet* InitializeStaticFileWaitHandleSet(moho::FWaitHandleSet& waitHandleSet)
  {
    if (waitHandleSet.mLock.mMutex == nullptr) {
      waitHandleSet.mLock.mMutex = new boost::mutex();
    }
    waitHandleSet.mLockLevel = 0;
    waitHandleSet.mWaitingLevel = 0;
    waitHandleSet.mIsLocked = 0;
    return &waitHandleSet;
  }

  /**
   * Address: 0x00413F20 (FUN_00413F20, sub_413F20)
   *
   * What it does:
   * Performs process-shutdown synchronization teardown for the static
   * wait-handle mutex lane.
   */
  void DestroyStaticFileWaitHandleSet(moho::FWaitHandleSet& waitHandleSet)
  {
    if (waitHandleSet.mLock.mMutex != nullptr) {
      waitHandleSet.mLock.mMutex->lock();
      waitHandleSet.mLock.mMutex->unlock();
      delete waitHandleSet.mLock.mMutex;
      waitHandleSet.mLock.mMutex = nullptr;
    }
  }

  /**
   * Address: 0x004580C0 (FUN_004580C0, sub_4580C0)
   * Address: 0x00BEF5A0 (FUN_00BEF5A0, sub_BEF5A0)
   *
   * What it does:
   * `atexit` hook that tears down static wait-handle runtime lanes (VFS pointer,
   * TLS lane, maps, intrusive list links, and synchronization lane).
   */
  void FileWaitHandleSetAtProcessExit()
  {
    ReleaseWaitHandleSetVfs(sFWaitHandleSet);
    sPFWaitHandleSet = nullptr;
    ReleaseWaitHandleThreadStateRuntime(sFWaitHandleSet.mThreadStateInd);
    ClearFileInfoMapStorage(sFWaitHandleSet.mFileInfo);
    ClearZipMapStorage(sFWaitHandleSet.mZipEntries);
    UnlinkWaitHandleSetSentinel(sFWaitHandleSet);
    DestroyStaticFileWaitHandleSet(sFWaitHandleSet);
  }
} // namespace

/**
 * Address: 0x00457FF0 (FUN_00457FF0, func_InitFileCWaitHandleSet)
 *
 * What it does:
 * Initializes process-global file wait-handle runtime storage and publishes
 * the singleton pointer.
 */
moho::FWaitHandleSet* moho::FILE_InitWaitHandleSet()
{
  (void)InitializeStaticFileWaitHandleSet(sFWaitHandleSet);
  sFWaitHandleSet.mPrev = reinterpret_cast<SFileWaitHandle*>(&sFWaitHandleSet.mPrev);
  sFWaitHandleSet.mNext = reinterpret_cast<SFileWaitHandle*>(&sFWaitHandleSet.mPrev);
  sFWaitHandleSet.mZipEntries = {};
  sFWaitHandleSet.mFileInfo = {};
  EnsureZipMapInitialized(sFWaitHandleSet.mZipEntries);
  EnsureFileInfoMapInitialized(sFWaitHandleSet.mFileInfo);
  sFWaitHandleSet.mHandle = nullptr;
  CreateDiskThreadStateRuntime(sFWaitHandleSet.mThreadStateInd);
  sPFWaitHandleSet = &sFWaitHandleSet;
  return sPFWaitHandleSet;
}

/**
 * Address: 0x00457F90 (FUN_00457F90, func_EnsureFileCWaitHandleSet)
 *
 * What it does:
 * Lazily ensures file wait-handle runtime storage is initialized and
 * globally published.
 */
void moho::FILE_EnsureWaitHandleSet()
{
  std::call_once(sFileWaitHandleSetInitOnce, [] {
    (void)FILE_InitWaitHandleSet();
    (void)std::atexit(&FileWaitHandleSetAtProcessExit);
  });

  if (sPFWaitHandleSet == nullptr) {
    sPFWaitHandleSet = &sFWaitHandleSet;
  }
}

/**
 * Address: 0x00457ED0 (FUN_00457ED0, Moho::GetFWaitHandleSet)
 *
 * What it does:
 * Returns the process-global file wait-handle runtime pointer.
 */
moho::FWaitHandleSet* moho::FILE_GetWaitHandleSet()
{
  FILE_EnsureWaitHandleSet();
  return sPFWaitHandleSet;
}

/**
 * Address: 0x00459C40 (FUN_00459C40, ?DISK_OpenFileRead@Moho@@YA?AV?$auto_ptr@VStream@gpg@@@std@@VStrArg@gpg@@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Opens one source path for read through the file wait-handle owner and
 * mounted zip-entry lookup chain.
 */
msvc8::auto_ptr<gpg::Stream> moho::DISK_OpenFileRead(const gpg::StrArg sourcePath)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return msvc8::auto_ptr<gpg::Stream>(nullptr);
  }

  return OpenFileReadFromWaitHandleSet(*sPFWaitHandleSet, sourcePath);
}

/**
 * Address: 0x00459B90 (FUN_00459B90, ?DISK_OpenFileWrite@Moho@@YA?AV?$auto_ptr@VStream@gpg@@@std@@VStrArg@gpg@@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Opens one source path for write using the legacy buffered FileStream lane.
 */
msvc8::auto_ptr<gpg::Stream> moho::DISK_OpenFileWrite(const gpg::StrArg sourcePath)
{
  return msvc8::auto_ptr<gpg::Stream>(
    new gpg::FileStream(sourcePath != nullptr ? sourcePath : "", gpg::Stream::ModeSend, 0u, 4096)
  );
}

/**
 * Address: 0x00459AF0 (FUN_00459AF0, ?DISK_MountZipFile@Moho@@YA?AVCDiskMountedZipHandle@1@VStrArg@gpg@@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Mounts one zip archive through the process wait-handle runtime and returns
 * the intrusive mounted-handle reference.
 */
moho::SFileWaitHandle* moho::DISK_MountZipFile(const gpg::StrArg sourcePath)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return nullptr;
  }

  return MountZipFile(*sPFWaitHandleSet, sourcePath);
}

/**
 * Address: 0x00459B30 (FUN_00459B30, ?DISK_GetFileInfo@Moho@@YA_NVStrArg@gpg@@PAUSDiskFileInfo@1@@Z)
 *
 * gpg::StrArg,Moho::SDiskFileInfo *,bool
 *
 * What it does:
 * Forwards metadata lookup to the process wait-handle runtime.
 */
bool moho::DISK_GetFileInfo(const gpg::StrArg sourcePath, SDiskFileInfo* const outInfo, const bool realOnly)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return false;
  }

  return sPFWaitHandleSet->GetFileInfo(sourcePath, outInfo, realOnly);
}

/**
 * Address: 0x00459CD0 (FUN_00459CD0, ?DISK_ReadFile@Moho@@YA?AU?$MemBuffer@D@gpg@@VStrArg@3@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Reads one source path into an owned mutable memory buffer through the
 * process wait-handle runtime.
 */
gpg::MemBuffer<char> moho::DISK_ReadFile(const gpg::StrArg sourcePath)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return {};
  }

  return sPFWaitHandleSet->ReadFile(sourcePath);
}

/**
 * Address: 0x00459D10 (FUN_00459D10, ?DISK_MemoryMapFile@Moho@@YA?AU?$MemBuffer@$$CBD@gpg@@VStrArg@3@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Maps one source path into an immutable shared byte view through the process
 * wait-handle runtime.
 */
gpg::MemBuffer<const char> moho::DISK_MemoryMapFile(const gpg::StrArg sourcePath)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return {};
  }

  return sPFWaitHandleSet->MemoryMapFile(sourcePath);
}

/**
 * Address: 0x00459D50 (FUN_00459D50, ?DISK_GetLastError@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ)
 *
 * What it does:
 * Returns a copy of the current thread-local disk error text.
 */
msvc8::string moho::DISK_GetLastError()
{
  msvc8::string copiedError{};
  if (const msvc8::string* const currentError = FWaitHandleSet::GetErrorString(); currentError != nullptr) {
    copiedError.assign_owned(currentError->view());
  }
  return copiedError;
}

/**
 * Address: 0x00459DC0 (FUN_00459DC0, ?DISK_GetVFS@Moho@@YAPAVCVirtualFileSystem@1@XZ)
 *
 * What it does:
 * Returns the process-global mounted virtual file-system owner pointer.
 */
moho::CVirtualFileSystem* moho::DISK_GetVFS()
{
  FILE_EnsureWaitHandleSet();
  return sPFWaitHandleSet != nullptr ? sPFWaitHandleSet->mHandle : nullptr;
}

/**
 * Address: 0x00459B60 (FUN_00459B60, ?DISK_InvalidateFileInfoCache@Moho@@YAXVStrArg@gpg@@@Z)
 *
 * gpg::StrArg
 *
 * What it does:
 * Invalidates one canonical file-info cache key in the global wait-handle
 * singleton.
 */
void moho::DISK_InvalidateFileInfoCache(const gpg::StrArg sourcePath)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return;
  }

  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet != nullptr) {
    sPFWaitHandleSet->InvalidateFileInfoCache(sourcePath);
  }
}

/**
 * Address: 0x00456BE0 (FUN_00456BE0, cfunc_DiskFindFiles)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DiskFindFilesL`.
 */
int moho::cfunc_DiskFindFiles(lua_State* const luaContext)
{
  return cfunc_DiskFindFilesL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00456C60 (FUN_00456C60, cfunc_DiskFindFilesL)
 *
 * What it does:
 * Enumerates mounted VFS paths that match `(directory, pattern)` and returns
 * a 1-based Lua string array.
 */
int moho::cfunc_DiskFindFilesL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDiskFindFilesHelpText, 2, argumentCount);
  }

  msvc8::vector<msvc8::string> foundPaths{};
  FILE_EnsureWaitHandleSet();

  LuaPlus::LuaStackObject patternArg(state, 2);
  const char* const pattern = lua_tostring(state->m_state, 2);
  if (pattern == nullptr) {
    patternArg.TypeError("string");
  }

  LuaPlus::LuaStackObject directoryArg(state, 1);
  const char* const directory = lua_tostring(state->m_state, 1);
  if (directory == nullptr) {
    directoryArg.TypeError("string");
  }

  sPFWaitHandleSet->mHandle->EnumerateFiles(directory, pattern, true, &foundPaths);

  lua_newtable(state->m_state);
  const int resultTableIndex = lua_gettop(state->m_state);
  for (std::size_t i = 0; i < foundPaths.size(); ++i) {
    lua_pushnumber(state->m_state, static_cast<lua_Number>(i + 1));
    lua_pushstring(state->m_state, foundPaths[i].c_str());
    lua_settable(state->m_state, resultTableIndex);
  }

  return 1;
}

/**
 * Address: 0x00456C00 (FUN_00456C00, func_DiskFindFiles_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `DiskFindFiles`.
 */
moho::CScrLuaInitForm* moho::func_DiskFindFiles_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "DiskFindFiles",
    &moho::cfunc_DiskFindFiles,
    nullptr,
    "<global>",
    kDiskFindFilesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00456E30 (FUN_00456E30, cfunc_DiskGetFileInfo)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DiskGetFileInfoL`.
 */
int moho::cfunc_DiskGetFileInfo(lua_State* const luaContext)
{
  return cfunc_DiskGetFileInfoL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00456EB0 (FUN_00456EB0, cfunc_DiskGetFileInfoL)
 *
 * What it does:
 * Resolves one mounted file path and returns Lua metadata details or `false`
 * when the file does not exist.
 */
int moho::cfunc_DiskGetFileInfoL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected %d args, but got %d",
      kDiskGetFileInfoHelpText,
      1,
      argumentCount
    );
  }

  FILE_EnsureWaitHandleSet();
  CVirtualFileSystem* const vfs = sPFWaitHandleSet->mHandle;

  LuaPlus::LuaStackObject filenameArg(state, 1);
  const char* const filename = lua_tostring(state->m_state, 1);
  if (filename == nullptr) {
    filenameArg.TypeError("string");
  }

  SDiskFileInfo fileInfo{};
  if (vfs->GetFileInfo(filename, &fileInfo)) {
    lua_newtable(state->m_state);
    const int infoTableIndex = lua_gettop(state->m_state);

    const LuaPlus::LuaStackObject flagsStack = CreateFlagsTableStackObject(state, infoTableIndex);
    LuaPlus::LuaObject flagsTable(flagsStack);
    flagsTable.SetBoolean("IsFolder", (fileInfo.mFileAttributes & FA_Directory) != 0);
    flagsTable.SetBoolean("ReadOnly", (fileInfo.mFileAttributes & FA_Readonly) != 0);
    flagsTable.SetInteger("SizeBytes", static_cast<std::int32_t>(fileInfo.mFileSize));

    const std::uint64_t rawTimestamp = (static_cast<std::uint64_t>(fileInfo.mLastWriteTime.dwHighDateTime) << 32U) |
                                       static_cast<std::uint64_t>(fileInfo.mLastWriteTime.dwLowDateTime);
    const msvc8::string timestampText = gpg::STR_Printf("%016llx", rawTimestamp);
    flagsTable.SetString("TimeStamp", timestampText.c_str());

    FILETIME localFileTime{};
    SYSTEMTIME systemTime{};
    (void)::FileTimeToLocalFileTime(&fileInfo.mLastWriteTime, &localFileTime);
    (void)::FileTimeToSystemTime(&localFileTime, &systemTime);

    LuaPlus::LuaObject writeTimeTable(state);
    writeTimeTable.AssignNewTable(state, 0, 0);
    flagsTable.SetObject("WriteTime", writeTimeTable);
    writeTimeTable.SetInteger("year", systemTime.wYear);
    writeTimeTable.SetInteger("month", systemTime.wMonth);
    writeTimeTable.SetInteger("mday", systemTime.wDay);
    writeTimeTable.SetInteger("wday", systemTime.wDayOfWeek);
    writeTimeTable.SetInteger("hour", systemTime.wHour);
    writeTimeTable.SetInteger("minute", systemTime.wMinute);
    writeTimeTable.SetInteger("second", systemTime.wSecond);
  } else {
    lua_pushboolean(state->m_state, 0);
    (void)lua_gettop(state->m_state);
  }

  return 1;
}

/**
 * Address: 0x00456E50 (FUN_00456E50, func_DiskGetFileInfo_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `DiskGetFileInfo`.
 */
moho::CScrLuaInitForm* moho::func_DiskGetFileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "DiskGetFileInfo",
    &moho::cfunc_DiskGetFileInfo,
    nullptr,
    "<global>",
    kDiskGetFileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x00457160 (FUN_00457160, cfunc_DiskToLocal)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DiskToLocalL`.
 */
int moho::cfunc_DiskToLocal(lua_State* const luaContext)
{
  return cfunc_DiskToLocalL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004571E0 (FUN_004571E0, cfunc_DiskToLocalL)
 *
 * What it does:
 * Converts one system path to mounted/local VFS path form.
 */
int moho::cfunc_DiskToLocalL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDiskToLocalHelpText, 1, argumentCount);
  }

  FILE_EnsureWaitHandleSet();
  CVirtualFileSystem* const vfs = sPFWaitHandleSet->mHandle;

  LuaPlus::LuaStackObject pathArg(state, 1);
  const char* const sourcePath = lua_tostring(state->m_state, 1);
  if (sourcePath == nullptr) {
    pathArg.TypeError("string");
  }

  msvc8::string mountedPath{};
  (void)vfs->ToMountedPath(&mountedPath, sourcePath);
  lua_pushstring(state->m_state, mountedPath.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00457180 (FUN_00457180, func_DiskToLocal_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `DiskToLocal`.
 */
moho::CScrLuaInitForm* moho::func_DiskToLocal_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "DiskToLocal",
    &moho::cfunc_DiskToLocal,
    nullptr,
    "<global>",
    kDiskToLocalHelpText
  );
  return &binder;
}

/**
 * Address: 0x004572E0 (FUN_004572E0, cfunc_Basename)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_BasenameL`.
 */
int moho::cfunc_Basename(lua_State* const luaContext)
{
  return cfunc_BasenameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00457360 (FUN_00457360, cfunc_BasenameL)
 *
 * What it does:
 * Returns the last path component for one input path, with optional
 * extension stripping.
 */
int moho::cfunc_BasenameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kBasenameHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject stripArg(state, 2);
  LuaPlus::LuaStackObject pathArg(state, 1);
  const char* const fullPath = lua_tostring(state->m_state, 1);
  if (fullPath == nullptr) {
    pathArg.TypeError("string");
  }

  const bool stripExtension = stripArg.GetBoolean();
  const msvc8::string basename = FILE_Base(fullPath, stripExtension);
  lua_pushstring(state->m_state, basename.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00457300 (FUN_00457300, func_Basename_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `Basename`.
 */
moho::CScrLuaInitForm* moho::func_Basename_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Basename",
    &moho::cfunc_Basename,
    nullptr,
    "<global>",
    kBasenameHelpText
  );
  return &binder;
}

/**
 * Address: 0x00457460 (FUN_00457460, cfunc_Dirname)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_DirnameL`.
 */
int moho::cfunc_Dirname(lua_State* const luaContext)
{
  return cfunc_DirnameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004574E0 (FUN_004574E0, cfunc_DirnameL)
 *
 * What it does:
 * Returns one path with trailing filename removed.
 */
int moho::cfunc_DirnameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDirnameHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject pathArg(state, 1);
  const char* const fullPath = lua_tostring(state->m_state, 1);
  if (fullPath == nullptr) {
    pathArg.TypeError("string");
  }

  const msvc8::string dirname = FILE_DirPrefix(fullPath);
  lua_pushstring(state->m_state, dirname.c_str());
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x00457480 (FUN_00457480, func_Dirname_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `Dirname`.
 */
moho::CScrLuaInitForm* moho::func_Dirname_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "Dirname",
    &moho::cfunc_Dirname,
    nullptr,
    "<global>",
    kDirnameHelpText
  );
  return &binder;
}

/**
 * Address: 0x004575C0 (FUN_004575C0, cfunc_FileCollapsePath)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_FileCollapsePathL`.
 */
int moho::cfunc_FileCollapsePath(lua_State* const luaContext)
{
  return cfunc_FileCollapsePathL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00457640 (FUN_00457640, cfunc_FileCollapsePathL)
 *
 * What it does:
 * Collapses one path (`/./`, `/../`) and returns `(collapsedPath, success)`.
 */
int moho::cfunc_FileCollapsePathL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected %d args, but got %d",
      kFileCollapsePathHelpText,
      1,
      argumentCount
    );
  }

  LuaPlus::LuaStackObject pathArg(state, 1);
  const char* const fullPath = lua_tostring(state->m_state, 1);
  if (fullPath == nullptr) {
    pathArg.TypeError("string");
  }

  bool success = false;
  const msvc8::string collapsedPath = FILE_CollapsePath(fullPath, &success);
  lua_pushstring(state->m_state, collapsedPath.c_str());
  (void)lua_gettop(state->m_state);
  lua_pushboolean(state->m_state, success ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 2;
}

/**
 * Address: 0x004575E0 (FUN_004575E0, func_FileCollapsePath_LuaFuncDef)
 *
 * What it does:
 * Returns/creates the global Lua binder definition for `FileCollapsePath`.
 */
moho::CScrLuaInitForm* moho::func_FileCollapsePath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    CoreLuaInitSet(),
    "FileCollapsePath",
    &moho::cfunc_FileCollapsePath,
    nullptr,
    "<global>",
    kFileCollapsePathHelpText
  );
  return &binder;
}

/**
 * Address: 0x00413F90 (FUN_00413F90, Moho::FWaitHandleSet::Wait)
 *
 * What it does:
 * Acquires one shared read lane for wait-handle state and waits while an
 * exclusive locker or queued lock waiters are active.
 */
void moho::FWaitHandleSet::Wait()
{
  boost::mutex::scoped_lock guard(EnsureFileWaitSetMutex(mLock));
  while (mIsLocked != 0 || mWaitingLevel != 0) {
    mObjectSender.wait(guard);
  }
  ++mLockLevel;
}

/**
 * Address: 0x00414030 (FUN_00414030, Moho::FWaitHandleSet::Notify)
 *
 * What it does:
 * Releases one shared read lane and wakes queued exclusive waiters when the
 * shared-reader count reaches zero.
 */
void moho::FWaitHandleSet::Notify()
{
  boost::mutex::scoped_lock guard(EnsureFileWaitSetMutex(mLock));
  --mLockLevel;
  if (mWaitingLevel != 0 && mLockLevel == 0) {
    mObjectSender.notify_all();
  }
}

/**
 * Address: 0x004140A0 (FUN_004140A0, Moho::FWaitHandleSet::Lock)
 *
 * What it does:
 * Acquires the exclusive lock lane, waiting for active readers and any
 * existing exclusive owner to drain.
 */
void moho::FWaitHandleSet::Lock()
{
  boost::mutex::scoped_lock guard(EnsureFileWaitSetMutex(mLock));
  if (mLockLevel != 0 || mIsLocked != 0) {
    ++mWaitingLevel;
    while (mLockLevel != 0 || mIsLocked != 0) {
      mObjectSender.wait(guard);
    }
    --mWaitingLevel;
  }
  mIsLocked = 1;
}

/**
 * Address: 0x00414140 (FUN_00414140, Moho::FWaitHandleSet::NotifyAll)
 *
 * What it does:
 * Releases the exclusive lock lane and wakes all waiters.
 */
void moho::FWaitHandleSet::NotifyAll()
{
  boost::mutex::scoped_lock guard(EnsureFileWaitSetMutex(mLock));
  mIsLocked = 0;
  mObjectSender.notify_all();
}

/**
 * Address: 0x00458BC0 (FUN_00458BC0, Moho::FWaitHandleSet::RemoveEntry)
 *
 * What it does:
 * Unlinks one zip wait-handle entry from the active-handle list, erases all
 * matching zip-map nodes, and destroys the detached handle object.
 */
void moho::FWaitHandleSet::RemoveEntry(SFileWaitHandle* const handle)
{
  if (handle == nullptr) {
    return;
  }

  Lock();
  if (handle->mLock != 0) {
    NotifyAll();
    return;
  }

  handle->mPrev->mNext = handle->mNext;
  handle->mNext->mPrev = handle->mPrev;
  handle->mNext = handle;
  handle->mPrev = handle;

  while (true) {
    FWHSZipEntryMapNode* const nodeToErase = FindZipNodeByHandle(mZipEntries, handle);
    if (IsZipMapSentinel(nodeToErase)) {
      break;
    }
    ZipMapEraseNode(mZipEntries, nodeToErase);
  }

  NotifyAll();
  delete handle;
}

/**
 * Address: 0x00458D30 (FUN_00458D30, Moho::FWaitHandleSet::GetFileInfo)
 *
 * What it does:
 * Resolves metadata for one canonical path through zip-entry records and the
 * cached file-info map, then falls back to Win32 file attributes.
 */
bool moho::FWaitHandleSet::GetFileInfo(const gpg::StrArg sourcePath, SDiskFileInfo* const outInfo, const bool realOnly)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return false;
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  Wait();
  FWHSZipEntryMapNode* const zipNode = ZipEntryFind(mZipEntries, canonicalPath);
  if (zipNode != nullptr && zipNode != mZipEntries.mHead) {
    SFileWaitHandle* const handle = zipNode->mEntry.mHandle;
    CZipFile* const zipFile = handle != nullptr ? handle->mZipFile : nullptr;
    const std::uint32_t zipEntryIndex = zipNode->mEntry.mZipEntryIndex;
    AddWaitHandleReference(handle);
    Notify();

    if (outInfo != nullptr) {
      outInfo->mFileAttributes = static_cast<EFileAttributes>(FA_Readonly | FA_Zipped);
      outInfo->mFileSize = zipFile != nullptr ? zipFile->GetEntrySize(zipEntryIndex) : 0;
      outInfo->mLastWriteTime = zipFile != nullptr ? zipFile->GetEntryLastModTime(zipEntryIndex) : FILETIME{};
    }

    ReleaseWaitHandleReference(handle);
    return true;
  }

  if (realOnly) {
    Notify();
    return false;
  }

  FWHSFileInfoMapNode* const cachedInfoNode = FileInfoFind(mFileInfo, canonicalPath);
  if (cachedInfoNode != nullptr && cachedInfoNode != mFileInfo.mHead) {
    if (outInfo != nullptr) {
      *outInfo = cachedInfoNode->mInfo;
    }
    const bool hasCachedWriteTime = HasWriteTime(cachedInfoNode->mInfo);
    Notify();
    return hasCachedWriteTime;
  }

  Notify();

  SDiskFileInfo diskInfo{};
  const bool queryOk = TryQueryFileAttributes(canonicalPath, &diskInfo);
  if (queryOk) {
    Lock();
    if (SDiskFileInfo* const cachedInfo = FileInfoMapGetOrCreate(mFileInfo, canonicalPath); cachedInfo != nullptr) {
      *cachedInfo = diskInfo;
    }
    NotifyAll();
  }

  if (outInfo != nullptr) {
    *outInfo = diskInfo;
  }
  return queryOk && HasWriteTime(diskInfo);
}

/**
 * Address: 0x00457F20 (FUN_00457F20, Moho::FWaitHandleSet::ErrorString)
 *
 * What it does:
 * Returns one thread-local error string storage lane for this wait-handle
 * set owner.
 */
msvc8::string* moho::FWaitHandleSet::ErrorString()
{
  return GetOrCreateDiskThreadStateValue(mThreadStateInd);
}

/**
 * Address: 0x00458280 (FUN_00458280, Moho::FWaitHandleSet::GetErrorString)
 *
 * What it does:
 * Returns the process-global wait-handle thread-local error string storage.
 */
msvc8::string* moho::FWaitHandleSet::GetErrorString()
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet != nullptr) {
    return sPFWaitHandleSet->ErrorString();
  }

  thread_local msvc8::string sFallbackError{};
  return &sFallbackError;
}

/**
 * Address: 0x00459300 (FUN_00459300, Moho::FWaitHandleSet::ReadFile)
 *
 * gpg::StrArg
 *
 * What it does:
 * Reads one canonicalized file path into an owned mutable memory buffer,
 * preferring mounted zip entries when present.
 */
gpg::MemBuffer<char> moho::FWaitHandleSet::ReadFile(const gpg::StrArg sourcePath)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return {};
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  ScopedWaitNotify notifyGuard(*this);

  FWHSZipEntryMapNode* const zipNode = ZipEntryFind(mZipEntries, canonicalPath);
  if (zipNode != nullptr && zipNode != mZipEntries.mHead && zipNode->mEntry.mHandle != nullptr) {
    SFileWaitHandle* const handle = zipNode->mEntry.mHandle;
    const std::uint32_t zipEntryIndex = zipNode->mEntry.mZipEntryIndex;
    ScopedHandleRef handleRef(handle);
    notifyGuard.NotifyNow();

    CZipFile* const zipFile = handle->mZipFile;
    if (zipFile == nullptr) {
      return {};
    }

    return zipFile->CopyEntry(zipEntryIndex);
  }

  const std::wstring sourcePathWide = gpg::STR_Utf8ToWide(canonicalPath.c_str());
  HANDLE fileHandle = ::CreateFileW(
    sourcePathWide.c_str(),
    GENERIC_READ,
    FILE_SHARE_READ,
    nullptr,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    nullptr
  );
  if (fileHandle == INVALID_HANDLE_VALUE) {
    SetWaitHandleErrorFromWin32(this);
    return {};
  }

  const DWORD fileSize = ::GetFileSize(fileHandle, nullptr);
  if (fileSize == INVALID_FILE_SIZE && ::GetLastError() != NO_ERROR) {
    SetWaitHandleErrorFromWin32(this);
    (void)::CloseHandle(fileHandle);
    return {};
  }

  gpg::MemBuffer<char> diskBytes = gpg::AllocMemBuffer(static_cast<std::size_t>(fileSize));
  if (fileSize != 0 && diskBytes.data() == nullptr) {
    (void)::CloseHandle(fileHandle);
    return {};
  }

  DWORD bytesRead = 0;
  const BOOL readOk = ::ReadFile(fileHandle, diskBytes.data(), fileSize, &bytesRead, nullptr);
  (void)::CloseHandle(fileHandle);
  if (readOk == FALSE || bytesRead != fileSize) {
    if (readOk == FALSE) {
      SetWaitHandleErrorFromWin32(this);
    } else {
      SetWaitHandleErrorString(this, gpg::STR_Printf("short read (%u/%u bytes)", bytesRead, fileSize));
    }
    return {};
  }

  return diskBytes;
}

/**
 * Address: 0x004596C0 (FUN_004596C0, Moho::FWaitHandleSet::MemoryMapFile)
 *
 * gpg::StrArg
 *
 * What it does:
 * Maps one canonicalized file path into an immutable shared memory view,
 * preferring mounted zip entries when present.
 */
gpg::MemBuffer<const char> moho::FWaitHandleSet::MemoryMapFile(const gpg::StrArg sourcePath)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return {};
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  ScopedWaitNotify notifyGuard(*this);

  FWHSZipEntryMapNode* const zipNode = ZipEntryFind(mZipEntries, canonicalPath);
  if (zipNode != nullptr && zipNode != mZipEntries.mHead && zipNode->mEntry.mHandle != nullptr) {
    SFileWaitHandle* const handle = zipNode->mEntry.mHandle;
    const std::uint32_t zipEntryIndex = zipNode->mEntry.mZipEntryIndex;
    ScopedHandleRef handleRef(handle);
    notifyGuard.NotifyNow();

    CZipFile* const zipFile = handle->mZipFile;
    if (zipFile == nullptr) {
      return {};
    }

    return zipFile->ReadEntry(zipEntryIndex);
  }

  const std::wstring sourcePathWide = gpg::STR_Utf8ToWide(canonicalPath.c_str());
  HANDLE fileHandle = ::CreateFileW(
    sourcePathWide.c_str(),
    GENERIC_READ,
    FILE_SHARE_READ,
    nullptr,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    nullptr
  );
  if (fileHandle == INVALID_HANDLE_VALUE) {
    SetWaitHandleErrorFromWin32(this);
    return {};
  }

  const DWORD fileSize = ::GetFileSize(fileHandle, nullptr);
  if (fileSize == INVALID_FILE_SIZE && ::GetLastError() != NO_ERROR) {
    SetWaitHandleErrorFromWin32(this);
    (void)::CloseHandle(fileHandle);
    return {};
  }

  HANDLE mappingHandle = ::CreateFileMappingW(fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
  if (mappingHandle == nullptr || mappingHandle == INVALID_HANDLE_VALUE) {
    SetWaitHandleErrorFromWin32(this);
    (void)::CloseHandle(fileHandle);
    return {};
  }

  const void* const mappedView = ::MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
  (void)::CloseHandle(mappingHandle);
  (void)::CloseHandle(fileHandle);
  if (mappedView == nullptr) {
    SetWaitHandleErrorFromWin32(this);
    return {};
  }

  const char* const begin = static_cast<const char*>(mappedView);
  const char* const end = begin + fileSize;
  boost::shared_ptr<const char> mappedOwner(begin, &UnmapFileView);
  return gpg::MemBuffer<const char>(mappedOwner, begin, end);
}

/**
 * Address: 0x00459070 (FUN_00459070, Moho::FWaitHandleSet::InvalidateFileInfoCache)
 *
 * What it does:
 * Canonicalizes one source path, acquires the exclusive lane, and removes all
 * matching cached file-info entries.
 */
void moho::FWaitHandleSet::InvalidateFileInfoCache(const gpg::StrArg sourcePath)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return;
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  Lock();
  (void)FileInfoMapRemoveByCanonicalPath(mFileInfo, canonicalPath);
  NotifyAll();
}

/**
 * Address: 0x00458D30 (FUN_00458D30, Moho::FWaitHandleSet::GetFileInfo)
 *
 * What it does:
 * Resolves file metadata through the wait-handle/VFS runtime when available.
 * The recovered `realOnly` gate is preserved for callsite parity.
 */
bool moho::FILE_GetFileInfo(const gpg::StrArg sourcePath, SDiskFileInfo* const outInfo, const bool realOnly)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return false;
  }

  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet != nullptr && sPFWaitHandleSet->mHandle != nullptr) {
    return sPFWaitHandleSet->mHandle->GetFileInfo(sourcePath, outInfo);
  }

  if (sPFWaitHandleSet != nullptr) {
    return sPFWaitHandleSet->GetFileInfo(sourcePath, outInfo, realOnly);
  }

  return false;
}

msvc8::string* moho::FILE_ToMountedPath(msvc8::string* const outPath, const gpg::StrArg sourcePath)
{
  if (outPath == nullptr) {
    return nullptr;
  }

  FILE_EnsureWaitHandleSet();
  outPath->assign_owned(sourcePath != nullptr ? sourcePath : "");

  if (sPFWaitHandleSet != nullptr && sPFWaitHandleSet->mHandle != nullptr) {
    return sPFWaitHandleSet->mHandle->ToMountedPath(outPath, outPath->c_str());
  }

  return outPath;
}
