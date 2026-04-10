#include "CDiskWatch.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/XFileError.h"

namespace moho
{
  msvc8::string WIN_GetLastError();
  std::uint32_t PLAT_GetCallStack(void* contextRecord, std::uint32_t maxFrames, std::uint32_t* outFrames);
}

using namespace moho;

namespace
{
  std::mutex gDiskWatchInitMutex;
  CDiskWatch* gDiskWatch = nullptr;
  constexpr std::uint8_t kWatchMapColorRed = 0u;
  constexpr std::uint8_t kWatchMapColorBlack = 1u;
  constexpr std::size_t kDefaultReadBufferSize = 0x1000u;
  constexpr DWORD kDirectoryNotifyFilter =
    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE;
  constexpr float kPendingEventDispatchDelayMs = 250.0f;
  constexpr const char* kEnablePrivilegesWarning =
    "CDiskWatch::EnablePrivileges: Unable to enable privilege: %s -- GetLastError(): %d "
    "Notifications may not work as intended due to insufficient access rights/process privileges.";
  constexpr const char* kReadDirectoryChangesFailedWarning = "CDiskWatch::Read() failed: %s";
  constexpr const char* kGetOverlappedResultFailedWarning = "CDiskWatch::Check(): GetOverlappedResult() failed: %s";

  CDiskWatchListener* LinkOwnerFromNode(TDatListItem<CDiskWatchListener, void>* node);

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
  int CompareDirectoryKeys(const msvc8::string& lhs, const msvc8::string& rhs)
  {
    return ComparePathViews(lhs.view(), rhs.view());
  }

  [[noreturn]] void ThrowFileWildError(const char* const message)
  {
    std::uint32_t callstack[32]{};
    const std::uint32_t frameCount = moho::PLAT_GetCallStack(nullptr, 32u, callstack);
    const msvc8::string fullMessage = gpg::STR_Printf(
      "%s: %s", "Moho::FILE_Wild", message != nullptr ? message : "File error."
    );
    throw moho::XFileError(fullMessage.to_std(), callstack, frameCount);
  }

  /**
   * Address: 0x00411500 (FUN_00411500, func_FileWildMatch)
   *
   * What it does:
   * Performs recursive wildcard matching with `*` and `?`, using case-folded
   * character comparison.
   */
  [[nodiscard]] bool FileWildMatch(const char* const path, const char* const pattern)
  {
    const char* currentPattern = pattern;
    const char token = *currentPattern;
    if (token == '\0') {
      return *path == '\0';
    }

    if (token == '*') {
      if (FileWildMatch(path, currentPattern + 1)) {
        return true;
      }
      if (*path == '\0') {
        return false;
      }
    } else if (token == '?') {
      return *path != '\0' && FileWildMatch(path + 1, currentPattern + 1);
    } else {
      const int pathFolded = std::tolower(static_cast<unsigned char>(*path));
      const int patternFolded = std::tolower(static_cast<unsigned char>(token));
      if (pathFolded != patternFolded) {
        return false;
      }
      currentPattern += 1;
    }

    return FileWildMatch(path + 1, currentPattern);
  }

  [[nodiscard]]
  OVERLAPPED* AsOverlapped(CDiskDirWatch& watch)
  {
    return reinterpret_cast<OVERLAPPED*>(&watch.mReadOverlapped);
  }

  [[nodiscard]]
  const OVERLAPPED* AsOverlapped(const CDiskDirWatch& watch)
  {
    return reinterpret_cast<const OVERLAPPED*>(&watch.mReadOverlapped);
  }

  [[nodiscard]]
  int ToDiskWatchActionCode(const DWORD notifyAction)
  {
    switch (notifyAction) {
      case FILE_ACTION_ADDED:
        return 1;
      case FILE_ACTION_REMOVED:
        return 2;
      case FILE_ACTION_MODIFIED:
        return 3;
      case FILE_ACTION_RENAMED_OLD_NAME:
        return 4;
      case FILE_ACTION_RENAMED_NEW_NAME:
        return 5;
      default:
        return 0;
    }
  }

  [[nodiscard]]
  msvc8::string NotifyFileNameToUtf8(const FILE_NOTIFY_INFORMATION& notifyRecord)
  {
    const std::wstring wideName(notifyRecord.FileName, notifyRecord.FileNameLength / sizeof(wchar_t));
    return gpg::STR_WideToUtf8(wideName.c_str());
  }

  void SetEventTimestampFromTimer(SDiskWatchEvent& event, const gpg::time::Timer& timer)
  {
    const std::uint64_t rawTimestamp = static_cast<std::uint64_t>(timer.mTime);
    event.mTimestampLow = static_cast<std::uint32_t>(rawTimestamp & 0xFFFFFFFFu);
    event.mTimestampHigh = static_cast<std::uint32_t>(rawTimestamp >> 32u);
  }

  [[nodiscard]]
  std::uint64_t GetEventTimestamp(const SDiskWatchEvent& event)
  {
    return (static_cast<std::uint64_t>(event.mTimestampHigh) << 32u) | static_cast<std::uint64_t>(event.mTimestampLow);
  }

  [[nodiscard]]
  bool IsPendingEventReady(const SDiskWatchEvent& event)
  {
    const std::uint64_t timestamp = GetEventTimestamp(event);
    const std::uint64_t now = static_cast<std::uint64_t>(gpg::time::GetCycle());
    const std::uint64_t elapsedCycles = now >= timestamp ? now - timestamp : 0u;
    return gpg::time::CyclesToMilliseconds(static_cast<LONGLONG>(elapsedCycles)) >= kPendingEventDispatchDelayMs;
  }

  [[nodiscard]]
  bool IsDuplicateEvent(
    const msvc8::vector<SDiskWatchEvent>& queuedEvents,
    const msvc8::string& eventPath,
    const int actionCode
  )
  {
    for (const auto& queuedEvent : queuedEvents) {
      if (queuedEvent.mActionCode == actionCode && CompareDirectoryKeys(queuedEvent.mPath, eventPath) == 0) {
        return true;
      }
    }
    return false;
  }

  void DispatchEventToListeners(CDiskWatch& owner, const SDiskWatchEvent& event)
  {
    using ListenerNode = TDatListItem<CDiskWatchListener, void>;

    ListenerNode* const listenersHead = &owner.mListeners;
    if (listenersHead->mNext == listenersHead) {
      return;
    }

    ListenerNode pendingHead{};
    pendingHead.mPrev = listenersHead->mPrev;
    pendingHead.mNext = listenersHead->mNext;
    pendingHead.mPrev->mNext = &pendingHead;
    pendingHead.mNext->mPrev = &pendingHead;

    listenersHead->mPrev = listenersHead;
    listenersHead->mNext = listenersHead;

    while (pendingHead.mNext != &pendingHead) {
      ListenerNode* const node = pendingHead.mNext;
      node->ListLinkBefore(listenersHead);

      CDiskWatchListener* const listener = LinkOwnerFromNode(node);
      if (listener != nullptr) {
        listener->OnEvent(event);
      }
    }
  }

  [[nodiscard]]
  bool IsFileStillWriterLocked(const SDiskWatchEvent& event)
  {
    if (event.mActionCode != FILE_ACTION_MODIFIED) {
      return false;
    }

    const std::wstring widePath = gpg::STR_Utf8ToWide(event.mPath.c_str());
    const HANDLE fileHandle = ::CreateFileW(
      widePath.c_str(),
      GENERIC_READ,
      FILE_SHARE_READ,
      nullptr,
      OPEN_EXISTING,
      FILE_READ_ATTRIBUTES,
      nullptr
    );

    const bool locked = fileHandle == INVALID_HANDLE_VALUE && ::GetLastError() == ERROR_SHARING_VIOLATION;
    if (fileHandle != INVALID_HANDLE_VALUE) {
      (void)::CloseHandle(fileHandle);
    }
    return locked;
  }

  [[nodiscard]]
  bool IsWatchMapSentinel(const CDiskWatch::DiskWatchMapNode* const node)
  {
    return node == nullptr || node->mIsNil != 0u;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapHead(const CDiskWatch::DiskWatchMap& map)
  {
    return map.mHead;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapRoot(const CDiskWatch::DiskWatchMap& map)
  {
    CDiskWatch::DiskWatchMapNode* const head = WatchMapHead(map);
    if (IsWatchMapSentinel(head)) {
      return head;
    }
    return head->mParent;
  }

  void EnsureDiskWatchMapInitialized(CDiskWatch::DiskWatchMap& map)
  {
    if (map.mHead != nullptr) {
      return;
    }

    CDiskWatch::DiskWatchMapNode* const head = new CDiskWatch::DiskWatchMapNode();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mDirectoryPath.clear();
    head->mDirWatch = nullptr;
    head->mColor = 1;
    head->mIsNil = 1;
    head->mPadding2E = 0;
    map.mAllocProxy = nullptr;
    map.mHead = head;
    map.mNodeCount = 0;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapLowerBound(
    const CDiskWatch::DiskWatchMap& map, const msvc8::string& directoryPath
  )
  {
    CDiskWatch::DiskWatchMapNode* result = WatchMapHead(map);
    if (result == nullptr) {
      return nullptr;
    }

    CDiskWatch::DiskWatchMapNode* node = result->mParent;
    while (!IsWatchMapSentinel(node)) {
      if (CompareDirectoryKeys(node->mDirectoryPath, directoryPath) >= 0) {
        result = node;
        node = node->mLeft;
      } else {
        node = node->mRight;
      }
    }

    return result;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapFind(const CDiskWatch::DiskWatchMap& map, const msvc8::string& directoryPath)
  {
    CDiskWatch::DiskWatchMapNode* const lowerBound = WatchMapLowerBound(map, directoryPath);
    if (lowerBound == nullptr || lowerBound == map.mHead) {
      return map.mHead;
    }

    return CompareDirectoryKeys(directoryPath, lowerBound->mDirectoryPath) < 0 ? map.mHead : lowerBound;
  }

  void WatchMapRotateLeft(CDiskWatch::DiskWatchMap& map, CDiskWatch::DiskWatchMapNode* const pivot)
  {
    if (IsWatchMapSentinel(pivot) || IsWatchMapSentinel(pivot->mRight)) {
      return;
    }

    CDiskWatch::DiskWatchMapNode* const head = WatchMapHead(map);
    CDiskWatch::DiskWatchMapNode* const right = pivot->mRight;

    pivot->mRight = right->mLeft;
    if (!IsWatchMapSentinel(right->mLeft)) {
      right->mLeft->mParent = pivot;
    }

    right->mParent = pivot->mParent;
    if (IsWatchMapSentinel(pivot->mParent)) {
      head->mParent = right;
    } else if (pivot == pivot->mParent->mLeft) {
      pivot->mParent->mLeft = right;
    } else {
      pivot->mParent->mRight = right;
    }

    right->mLeft = pivot;
    pivot->mParent = right;
  }

  void WatchMapRotateRight(CDiskWatch::DiskWatchMap& map, CDiskWatch::DiskWatchMapNode* const pivot)
  {
    if (IsWatchMapSentinel(pivot) || IsWatchMapSentinel(pivot->mLeft)) {
      return;
    }

    CDiskWatch::DiskWatchMapNode* const head = WatchMapHead(map);
    CDiskWatch::DiskWatchMapNode* const left = pivot->mLeft;

    pivot->mLeft = left->mRight;
    if (!IsWatchMapSentinel(left->mRight)) {
      left->mRight->mParent = pivot;
    }

    left->mParent = pivot->mParent;
    if (IsWatchMapSentinel(pivot->mParent)) {
      head->mParent = left;
    } else if (pivot == pivot->mParent->mRight) {
      pivot->mParent->mRight = left;
    } else {
      pivot->mParent->mLeft = left;
    }

    left->mRight = pivot;
    pivot->mParent = left;
  }

  void WatchMapInsertFixup(CDiskWatch::DiskWatchMap& map, CDiskWatch::DiskWatchMapNode* node)
  {
    while (!IsWatchMapSentinel(node->mParent) && node->mParent->mColor == 0u) {
      CDiskWatch::DiskWatchMapNode* const parent = node->mParent;
      CDiskWatch::DiskWatchMapNode* const grandparent = parent->mParent;

      if (parent == grandparent->mLeft) {
        CDiskWatch::DiskWatchMapNode* uncle = grandparent->mRight;
        if (!IsWatchMapSentinel(uncle) && uncle->mColor == 0u) {
          parent->mColor = 1;
          uncle->mColor = 1;
          grandparent->mColor = 0;
          node = grandparent;
        } else {
          if (node == parent->mRight) {
            node = parent;
            WatchMapRotateLeft(map, node);
          }
          node->mParent->mColor = 1;
          node->mParent->mParent->mColor = 0;
          WatchMapRotateRight(map, node->mParent->mParent);
        }
      } else {
        CDiskWatch::DiskWatchMapNode* uncle = grandparent->mLeft;
        if (!IsWatchMapSentinel(uncle) && uncle->mColor == 0u) {
          parent->mColor = 1;
          uncle->mColor = 1;
          grandparent->mColor = 0;
          node = grandparent;
        } else {
          if (node == parent->mLeft) {
            node = parent;
            WatchMapRotateRight(map, node);
          }
          node->mParent->mColor = 1;
          node->mParent->mParent->mColor = 0;
          WatchMapRotateLeft(map, node->mParent->mParent);
        }
      }
    }

    CDiskWatch::DiskWatchMapNode* const root = WatchMapRoot(map);
    if (!IsWatchMapSentinel(root)) {
      root->mColor = 1;
      root->mParent = WatchMapHead(map);
    }
  }

  [[nodiscard]]
  bool WatchMapInsert(CDiskWatch::DiskWatchMap& map, const msvc8::string& directoryPath, CDiskDirWatch* const dirWatch)
  {
    EnsureDiskWatchMapInitialized(map);
    CDiskWatch::DiskWatchMapNode* const head = map.mHead;
    if (head == nullptr) {
      return false;
    }

    if (WatchMapFind(map, directoryPath) != head) {
      return false;
    }

    std::unique_ptr<CDiskWatch::DiskWatchMapNode> insertedOwner = std::make_unique<CDiskWatch::DiskWatchMapNode>();
    CDiskWatch::DiskWatchMapNode* const insertedNode = insertedOwner.get();
    insertedNode->mLeft = head;
    insertedNode->mParent = head;
    insertedNode->mRight = head;
    insertedNode->mDirectoryPath.assign_owned(directoryPath.view());
    insertedNode->mDirWatch = dirWatch;
    insertedNode->mColor = 0;
    insertedNode->mIsNil = 0;
    insertedNode->mPadding2E = 0;

    CDiskWatch::DiskWatchMapNode* parent = head;
    CDiskWatch::DiskWatchMapNode* node = head->mParent;
    bool insertAsLeftChild = true;
    while (!IsWatchMapSentinel(node)) {
      parent = node;
      if (CompareDirectoryKeys(directoryPath, node->mDirectoryPath) < 0) {
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
      if (head->mLeft == parent || CompareDirectoryKeys(insertedNode->mDirectoryPath, head->mLeft->mDirectoryPath) < 0) {
        head->mLeft = insertedNode;
      }
    } else {
      parent->mRight = insertedNode;
      if (head->mRight == parent || CompareDirectoryKeys(insertedNode->mDirectoryPath, head->mRight->mDirectoryPath) > 0) {
        head->mRight = insertedNode;
      }
    }

    ++map.mNodeCount;
    insertedOwner.release();
    WatchMapInsertFixup(map, insertedNode);
    return true;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* NextWatchMapNode(
    CDiskWatch::DiskWatchMapNode* node, const CDiskWatch::DiskWatchMapNode* const head
  )
  {
    if (node == nullptr || head == nullptr) {
      return nullptr;
    }

    if (node->mRight != nullptr && node->mRight->mIsNil == 0u) {
      node = node->mRight;
      while (node->mLeft != nullptr && node->mLeft->mIsNil == 0u) {
        node = node->mLeft;
      }
      return node;
    }

    CDiskWatch::DiskWatchMapNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }

    return parent;
  }

  [[nodiscard]]
  bool IsWatchMapNodeBlack(const CDiskWatch::DiskWatchMapNode* const node)
  {
    return IsWatchMapSentinel(node) || node->mColor == kWatchMapColorBlack;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapMinimumNode(CDiskWatch::DiskWatchMapNode* node)
  {
    while (!IsWatchMapSentinel(node->mLeft)) {
      node = node->mLeft;
    }
    return node;
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapMaximumNode(CDiskWatch::DiskWatchMapNode* node)
  {
    while (!IsWatchMapSentinel(node->mRight)) {
      node = node->mRight;
    }
    return node;
  }

  void WatchMapEraseFixup(
    CDiskWatch::DiskWatchMap& map,
    CDiskWatch::DiskWatchMapNode* node,
    CDiskWatch::DiskWatchMapNode* parent
  )
  {
    CDiskWatch::DiskWatchMapNode* const head = WatchMapHead(map);

    while (node != head->mParent && IsWatchMapNodeBlack(node)) {
      if (node == parent->mLeft) {
        CDiskWatch::DiskWatchMapNode* sibling = parent->mRight;

        if (!IsWatchMapSentinel(sibling) && sibling->mColor == kWatchMapColorRed) {
          sibling->mColor = kWatchMapColorBlack;
          parent->mColor = kWatchMapColorRed;
          WatchMapRotateLeft(map, parent);
          sibling = parent->mRight;
        }

        if (IsWatchMapSentinel(sibling)) {
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsWatchMapNodeBlack(sibling->mLeft) && IsWatchMapNodeBlack(sibling->mRight)) {
          sibling->mColor = kWatchMapColorRed;
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsWatchMapNodeBlack(sibling->mRight)) {
          if (!IsWatchMapSentinel(sibling->mLeft)) {
            sibling->mLeft->mColor = kWatchMapColorBlack;
          }
          sibling->mColor = kWatchMapColorRed;
          WatchMapRotateRight(map, sibling);
          sibling = parent->mRight;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = kWatchMapColorBlack;
        if (!IsWatchMapSentinel(sibling->mRight)) {
          sibling->mRight->mColor = kWatchMapColorBlack;
        }
        WatchMapRotateLeft(map, parent);
      } else {
        CDiskWatch::DiskWatchMapNode* sibling = parent->mLeft;

        if (!IsWatchMapSentinel(sibling) && sibling->mColor == kWatchMapColorRed) {
          sibling->mColor = kWatchMapColorBlack;
          parent->mColor = kWatchMapColorRed;
          WatchMapRotateRight(map, parent);
          sibling = parent->mLeft;
        }

        if (IsWatchMapSentinel(sibling)) {
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsWatchMapNodeBlack(sibling->mRight) && IsWatchMapNodeBlack(sibling->mLeft)) {
          sibling->mColor = kWatchMapColorRed;
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsWatchMapNodeBlack(sibling->mLeft)) {
          if (!IsWatchMapSentinel(sibling->mRight)) {
            sibling->mRight->mColor = kWatchMapColorBlack;
          }
          sibling->mColor = kWatchMapColorRed;
          WatchMapRotateLeft(map, sibling);
          sibling = parent->mLeft;
        }

        sibling->mColor = parent->mColor;
        parent->mColor = kWatchMapColorBlack;
        if (!IsWatchMapSentinel(sibling->mLeft)) {
          sibling->mLeft->mColor = kWatchMapColorBlack;
        }
        WatchMapRotateRight(map, parent);
      }

      break;
    }

    if (!IsWatchMapSentinel(node)) {
      node->mColor = kWatchMapColorBlack;
    }
  }

  [[nodiscard]]
  CDiskWatch::DiskWatchMapNode* WatchMapEraseNode(
    CDiskWatch::DiskWatchMap& map, CDiskWatch::DiskWatchMapNode* const eraseTarget
  )
  {
    CDiskWatch::DiskWatchMapNode* const head = map.mHead;
    if (IsWatchMapSentinel(eraseTarget) || IsWatchMapSentinel(head)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    CDiskWatch::DiskWatchMapNode* const next = NextWatchMapNode(eraseTarget, head);
    CDiskWatch::DiskWatchMapNode* fixupNode = nullptr;
    CDiskWatch::DiskWatchMapNode* fixupParent = nullptr;

    if (IsWatchMapSentinel(eraseTarget->mLeft)) {
      fixupNode = eraseTarget->mRight;
      fixupParent = eraseTarget->mParent;
      if (!IsWatchMapSentinel(fixupNode)) {
        fixupNode->mParent = fixupParent;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = fixupNode;
      } else if (fixupParent->mLeft == eraseTarget) {
        fixupParent->mLeft = fixupNode;
      } else {
        fixupParent->mRight = fixupNode;
      }

      if (head->mLeft == eraseTarget) {
        head->mLeft = IsWatchMapSentinel(fixupNode) ? fixupParent : WatchMapMinimumNode(fixupNode);
      }
      if (head->mRight == eraseTarget) {
        head->mRight = IsWatchMapSentinel(fixupNode) ? fixupParent : WatchMapMaximumNode(fixupNode);
      }
    } else if (IsWatchMapSentinel(eraseTarget->mRight)) {
      fixupNode = eraseTarget->mLeft;
      fixupParent = eraseTarget->mParent;
      if (!IsWatchMapSentinel(fixupNode)) {
        fixupNode->mParent = fixupParent;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = fixupNode;
      } else if (fixupParent->mLeft == eraseTarget) {
        fixupParent->mLeft = fixupNode;
      } else {
        fixupParent->mRight = fixupNode;
      }

      if (head->mLeft == eraseTarget) {
        head->mLeft = IsWatchMapSentinel(fixupNode) ? fixupParent : WatchMapMinimumNode(fixupNode);
      }
      if (head->mRight == eraseTarget) {
        head->mRight = IsWatchMapSentinel(fixupNode) ? fixupParent : WatchMapMaximumNode(fixupNode);
      }
    } else {
      CDiskWatch::DiskWatchMapNode* const successor = next;
      fixupNode = successor->mRight;

      if (successor == eraseTarget->mRight) {
        fixupParent = successor;
      } else {
        fixupParent = successor->mParent;
        if (!IsWatchMapSentinel(fixupNode)) {
          fixupNode->mParent = fixupParent;
        }
        fixupParent->mLeft = fixupNode;

        successor->mRight = eraseTarget->mRight;
        successor->mRight->mParent = successor;
      }

      if (head->mParent == eraseTarget) {
        head->mParent = successor;
      } else if (eraseTarget->mParent->mLeft == eraseTarget) {
        eraseTarget->mParent->mLeft = successor;
      } else {
        eraseTarget->mParent->mRight = successor;
      }

      successor->mParent = eraseTarget->mParent;
      successor->mLeft = eraseTarget->mLeft;
      successor->mLeft->mParent = successor;
      std::swap(successor->mColor, eraseTarget->mColor);
    }

    if (eraseTarget->mColor == kWatchMapColorBlack) {
      WatchMapEraseFixup(map, fixupNode, fixupParent);
    }

    delete eraseTarget;
    if (map.mNodeCount > 0u) {
      --map.mNodeCount;
    }

    return next;
  }

  void DestroyDiskWatchMap(CDiskWatch::DiskWatchMap& map)
  {
    CDiskWatch::DiskWatchMapNode* const head = map.mHead;
    if (head == nullptr) {
      return;
    }

    CDiskWatch::DiskWatchMapNode* node = head->mLeft;
    while (!IsWatchMapSentinel(node) && node != head) {
      CDiskWatch::DiskWatchMapNode* const next = NextWatchMapNode(node, head);
      delete node->mDirWatch;
      node->mDirWatch = nullptr;
      delete node;
      node = next;
    }

    delete head;
    map.mAllocProxy = nullptr;
    map.mHead = nullptr;
    map.mNodeCount = 0;
  }

  /**
   * Address: 0x00463220 (FUN_00463220, disk-watch singleton init helper)
   *
   * What it does:
   * Lazily creates the process-wide CDiskWatch singleton and registers reset
   * cleanup with `atexit`.
   */
  void EnsureDiskWatchInitialized()
  {
    std::lock_guard<std::mutex> lock(gDiskWatchInitMutex);
    if (gDiskWatch != nullptr) {
      return;
    }

    gDiskWatch = new CDiskWatch();
    std::atexit(&DISK_ResetWatch);
  }

  CDiskWatchListener* LinkOwnerFromNode(TDatListItem<CDiskWatchListener, void>* const node)
  {
    using DiskWatchList = TDatList<CDiskWatchListener, void>;
    return DiskWatchList::template owner_from_member_node<CDiskWatchListener, &CDiskWatchListener::mLink>(node);
  }
} // namespace

/**
 * Address: 0x00411320 (?FILE_Wild@Moho@@YA_NVStrArg@gpg@@0_ND@Z)
 */
bool moho::FILE_Wild(const gpg::StrArg path, const gpg::StrArg pattern, const bool caseSensitive, const char /*pathSeparator*/)
{
  (void)caseSensitive;

  if (path == nullptr || path[0] == '\0') {
    ThrowFileWildError("Null argument.");
  }
  if (pattern == nullptr || pattern[0] == '\0') {
    ThrowFileWildError("Null argument.");
  }

  std::string normalizedPath(path);
  if (normalizedPath.find('.') == std::string::npos) {
    normalizedPath.push_back('.');
  }

  std::string patternList(pattern);
  char* currentPattern = patternList.data();
  while (currentPattern != nullptr) {
    char* separator = std::strchr(currentPattern, ';');
    if (separator != nullptr) {
      *separator = '\0';
    }

    if (FileWildMatch(normalizedPath.c_str(), currentPattern)) {
      return true;
    }

    if (separator == nullptr) {
      return false;
    }
    currentPattern = separator + 1;
  }

  return false;
}

/**
 * Address: 0x00461EF0 (FUN_00461EF0, ??0CDiskDirWatch@Moho@@QAE@PAVCDiskWatch@1@VStrArg@gpg@@@Z)
 */
CDiskDirWatch::CDiskDirWatch(CDiskWatch* const owner, const gpg::StrArg directoryPath)
  : mOwner(owner)
  , mPendingEvents()
  , mDirectoryPath(gpg::STR_Chop(directoryPath, '/'))
  , mDirectoryHandle(INVALID_HANDLE_VALUE)
  , mReadBuffer()
  , mReadOverlapped{}
{
  mReadBuffer.resize(kDefaultReadBufferSize, 0u);

  const char* const watchPath = mDirectoryPath.c_str();
  const HANDLE watchHandle = ::CreateFileA(
    watchPath,
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    nullptr,
    OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
    nullptr
  );
  mDirectoryHandle = watchHandle;

  if (watchHandle == INVALID_HANDLE_VALUE) {
    const msvc8::string errorText = WIN_GetLastError();
    gpg::Warnf("CDiskWatch(\"%s\") failed: %s", watchPath, errorText.c_str());
    return;
  }

  gpg::Logf("Watching directory \"%s\"", directoryPath != nullptr ? directoryPath : "");
  DoRead();
}

/**
 * Address: 0x00462020 (FUN_00462020, ??1CDiskDirWatch@Moho@@QAE@XZ)
 */
CDiskDirWatch::~CDiskDirWatch()
{
  const HANDLE watchHandle = static_cast<HANDLE>(mDirectoryHandle);
  if (watchHandle != INVALID_HANDLE_VALUE) {
    (void)::CancelIo(watchHandle);
    (void)::CloseHandle(watchHandle);
  }
  mDirectoryHandle = INVALID_HANDLE_VALUE;

  mReadBuffer.clear();
  mPendingEvents.clear();
}

/**
 * Address: 0x00462700 (FUN_00462700, ?DoRead@CDiskDirWatch@Moho@@AAEXXZ)
 *
 * What it does:
 * Resets the overlapped state and schedules one asynchronous
 * `ReadDirectoryChangesW` pass for this watched directory.
 */
void CDiskDirWatch::DoRead()
{
  const HANDLE watchHandle = static_cast<HANDLE>(mDirectoryHandle);
  if (watchHandle == INVALID_HANDLE_VALUE || mReadBuffer.empty()) {
    return;
  }

  std::memset(&mReadOverlapped, 0, sizeof(mReadOverlapped));

  const BOOL readQueued = ::ReadDirectoryChangesW(
    watchHandle,
    mReadBuffer.data(),
    static_cast<DWORD>(mReadBuffer.size()),
    TRUE,
    kDirectoryNotifyFilter,
    nullptr,
    AsOverlapped(*this),
    nullptr
  );
  if (readQueued != FALSE) {
    return;
  }

  const msvc8::string errorText = WIN_GetLastError();
  gpg::Warnf(kReadDirectoryChangesFailedWarning, errorText.c_str());
  (void)::CloseHandle(watchHandle);
  mDirectoryHandle = INVALID_HANDLE_VALUE;
}

/**
 * Address: 0x004620B0 (FUN_004620B0, ?Update@CDiskDirWatch@Moho@@QAEXXZ)
 *
 * What it does:
 * Drains completed directory-change reads into pending events, re-arms
 * asynchronous reads, and dispatches settled events to watch listeners.
 */
void CDiskDirWatch::Update()
{
  HANDLE watchHandle = static_cast<HANDLE>(mDirectoryHandle);
  while (watchHandle != INVALID_HANDLE_VALUE) {
    DWORD transferredBytes = 0;
    if (::GetOverlappedResult(watchHandle, AsOverlapped(*this), &transferredBytes, FALSE) != FALSE) {
      msvc8::vector<SDiskWatchEvent> queuedEvents{};

      if (!mReadBuffer.empty()) {
        auto* notifyRecord = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(mReadBuffer.data());
        while (notifyRecord != nullptr) {
          const msvc8::string leafNameUtf8 = NotifyFileNameToUtf8(*notifyRecord);

          SDiskWatchEvent event{};
          event.mPath = gpg::STR_Printf("%s\\%s", mDirectoryPath.c_str(), leafNameUtf8.c_str());
          event.mActionCode = ToDiskWatchActionCode(notifyRecord->Action);

          const gpg::time::Timer timestamp{};
          SetEventTimestampFromTimer(event, timestamp);

          if (!IsDuplicateEvent(queuedEvents, event.mPath, event.mActionCode)) {
            queuedEvents.push_back(event);
          }

          if (notifyRecord->NextEntryOffset == 0u) {
            break;
          }

          notifyRecord = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
            reinterpret_cast<const std::uint8_t*>(notifyRecord) + notifyRecord->NextEntryOffset
          );
        }
      }

      for (const auto& event : queuedEvents) {
        mPendingEvents.push_back(event);
      }

      DoRead();
    } else {
      if (::GetLastError() == ERROR_IO_INCOMPLETE) {
        break;
      }

      const msvc8::string errorText = WIN_GetLastError();
      gpg::Warnf(kGetOverlappedResultFailedWarning, errorText.c_str());
      DoRead();
    }

    watchHandle = static_cast<HANDLE>(mDirectoryHandle);
  }

  for (auto* eventIt = mPendingEvents.begin(); eventIt != mPendingEvents.end();) {
    if (!IsPendingEventReady(*eventIt)) {
      ++eventIt;
      continue;
    }

    if (!IsFileStillWriterLocked(*eventIt)) {
      DISK_InvalidateFileInfoCache(eventIt->mPath.c_str());

      if (mOwner != nullptr) {
        DispatchEventToListeners(*mOwner, *eventIt);
      }
    }

    eventIt = mPendingEvents.erase(eventIt);
  }
}

bool CDiskDirWatch::HasValidHandle() const
{
  return static_cast<HANDLE>(mDirectoryHandle) != INVALID_HANDLE_VALUE;
}

/**
 * Address: 0x00461B10 (FUN_00461B10, ??0CDiskWatchListener@Moho@@QAE@VStrArg@gpg@@@Z)
 */
CDiskWatchListener::CDiskWatchListener(const gpg::StrArg patterns)
  : mLink()
  , mWatch(nullptr)
  , mEvents()
  , mPatterns()
{
  if (patterns && patterns[0] != '\0') {
    mPatterns.push_back(msvc8::string(patterns));
    DISK_AddWatchListener(this);
  }
}

/**
 * Address: 0x00461C30 (FUN_00461C30, ??1CDiskWatchListener@Moho@@QAE@XZ)
 */
CDiskWatchListener::~CDiskWatchListener()
{
  if (mWatch != nullptr) {
    mWatch->RemoveListener(this);
  }
  mPatterns.clear();
  mEvents.clear();
  mLink.ListUnlink();
}

/**
 * Address: 0x00461DC0 (FUN_00461DC0, ?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
 */
void CDiskWatchListener::OnEvent(const SDiskWatchEvent& event)
{
  if (FilterEvent(event)) {
    OnDiskWatchEvent(event);
  }
}

/**
 * Address: 0x00461D00 (FUN_00461D00, ?FilterEvent@CDiskWatchListener@Moho@@UAE_NABUSDiskWatchEvent@2@@Z)
 */
bool CDiskWatchListener::FilterEvent(const SDiskWatchEvent& event)
{
  if (mPatterns.empty()) {
    return true;
  }

  const char* const path = event.mPath.c_str();
  for (const auto& pattern : mPatterns) {
    if (FILE_Wild(path, pattern.c_str())) {
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x00461DF0 (FUN_00461DF0, ?OnDiskWatchEvent@CDiskWatchListener@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
 */
void CDiskWatchListener::OnDiskWatchEvent(const SDiskWatchEvent& event)
{
  mEvents.push_back(event);
}

/**
 * Address: 0x00461E90 (FUN_00461E90, ?AnyChangesPending@CDiskWatchListener@Moho@@QAE_NXZ)
 */
bool CDiskWatchListener::AnyChangesPending()
{
  if (mWatch == nullptr) {
    return !mEvents.empty();
  }

  gpg::core::func_LockShared(&mWatch->mLock);
  const bool pending = !mEvents.empty();
  gpg::core::func_UnlockShared(&mWatch->mLock);
  return pending;
}

/**
 * Address: 0x00461E00 (FUN_00461E00,
 * ?CopyAndClearPendingChanges@CDiskWatchListener@Moho@@QAE?AV?$vector@USDiskWatchEvent@Moho@@V?$allocator@USDiskWatchEvent@Moho@@@std@@@std@@XZ)
 */
void CDiskWatchListener::CopyAndClearPendingChanges(msvc8::vector<SDiskWatchEvent>& outEvents)
{
  outEvents = msvc8::vector<SDiskWatchEvent>{};

  if (mWatch == nullptr) {
    std::swap(outEvents, mEvents);
    return;
  }

  gpg::core::func_LockShared(&mWatch->mLock);
  std::swap(outEvents, mEvents);
  gpg::core::func_UnlockShared(&mWatch->mLock);
}

/**
 * Address: 0x004627C0 (FUN_004627C0, ??0CDiskWatch@Moho@@QAE@XZ)
 */
CDiskWatch::CDiskWatch()
  : mListeners()
  , mUnknown08(nullptr)
  , mLock()
  , mOpaque10{}
  , mDirWatchMap{}
{
  mListeners.mPrev = &mListeners;
  mListeners.mNext = &mListeners;
  (void)EnablePrivileges();
}

/**
 * Address: 0x004628C0 (FUN_004628C0, ??1CDiskWatch@Moho@@QAE@XZ)
 *
 * What it does:
 * Unlinks listeners, releases watched-directory nodes, and destroys map/lock
 * state (`0x00462870` is the in-function cleanup block).
 */
CDiskWatch::~CDiskWatch()
{
  for (auto* node = mListeners.mNext; node != &mListeners;) {
    auto* const next = node->mNext;
    CDiskWatchListener* const listener = LinkOwnerFromNode(node);
    listener->mLink.ListUnlink();
    listener->mWatch = nullptr;
    node = next;
  }

  DestroyDiskWatchMap(mDirWatchMap);
}

/**
 * Address: 0x00462A30 (FUN_00462A30, ?AddListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
 */
void CDiskWatch::AddListener(CDiskWatchListener* const listener)
{
  if (listener == nullptr) {
    return;
  }

  gpg::core::func_LockShared(&mLock);
  listener->mLink.ListLinkBefore(&mListeners);
  listener->mWatch = this;
  gpg::core::func_UnlockShared(&mLock);
}

/**
 * Address: 0x00462A80 (FUN_00462A80, ?RemoveListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
 */
void CDiskWatch::RemoveListener(CDiskWatchListener* const listener)
{
  if (listener == nullptr) {
    return;
  }

  gpg::core::func_LockShared(&mLock);
  listener->mLink.ListUnlink();
  listener->mWatch = nullptr;
  gpg::core::func_UnlockShared(&mLock);
}

/**
 * Address: 0x00462AC0 (FUN_00462AC0, ?AddDirectory@CDiskWatch@Moho@@QAE_NVStrArg@gpg@@@Z)
 */
bool CDiskWatch::AddDirectory(const gpg::StrArg directoryPath)
{
  gpg::core::func_LockShared(&mLock);

  const msvc8::string normalizedPath = gpg::STR_ToLower(directoryPath);
  if (normalizedPath.empty()) {
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  EnsureDiskWatchMapInitialized(mDirWatchMap);
  if (WatchMapFind(mDirWatchMap, normalizedPath) != mDirWatchMap.mHead) {
    gpg::Warnf("CDiskWatch::AddDirectory(): Attempting to add \"%s\" multiple times.", normalizedPath.c_str());
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  std::unique_ptr<CDiskDirWatch> dirWatch = std::make_unique<CDiskDirWatch>(this, normalizedPath.c_str());
  if (!dirWatch->HasValidHandle()) {
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  if (!WatchMapInsert(mDirWatchMap, normalizedPath, dirWatch.get())) {
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  dirWatch.release();
  gpg::core::func_UnlockShared(&mLock);
  return true;
}

/**
 * Address: 0x00462DD0 (FUN_00462DD0, ?RemoveDirectoryW@CDiskWatch@Moho@@QAE_NVStrArg@gpg@@@Z)
 */
bool CDiskWatch::RemoveDirectoryW(const gpg::StrArg directoryPath)
{
  gpg::core::func_LockShared(&mLock);

  const msvc8::string normalizedPath = gpg::STR_ToLower(directoryPath);
  DiskWatchMapNode* const head = mDirWatchMap.mHead;
  DiskWatchMapNode* const node = head != nullptr ? WatchMapFind(mDirWatchMap, normalizedPath) : nullptr;
  if (node == nullptr || node == head) {
    gpg::Warnf("CDiskWatch::RemoveDirectory(): \"%s\" not being watched.", normalizedPath.c_str());
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  delete node->mDirWatch;
  node->mDirWatch = nullptr;
  (void)WatchMapEraseNode(mDirWatchMap, node);

  gpg::core::func_UnlockShared(&mLock);
  return true;
}

/**
 * Address: 0x00462F80 (?EnablePrivileges@CDiskWatch@Moho@@ABE_NXZ)
 */
bool CDiskWatch::EnablePrivileges() const
{
  msvc8::vector<msvc8::string> privilegeNames{};
  privilegeNames.push_back(gpg::STR_WideToUtf8(L"SeBackupPrivilege"));
  privilegeNames.push_back(gpg::STR_WideToUtf8(L"SeRestorePrivilege"));
  privilegeNames.push_back(gpg::STR_WideToUtf8(L"SeChangeNotifyPrivilege"));

  bool allPrivilegesEnabled = true;
  for (const auto& privilegeName : privilegeNames) {
    if (EnablePrivilege(privilegeName, true)) {
      continue;
    }

    const DWORD lastError = ::GetLastError();
    gpg::Warnf(kEnablePrivilegesWarning, privilegeName.c_str(), lastError);
    allPrivilegesEnabled = false;
  }

  return allPrivilegesEnabled;
}

/**
 * Address: 0x00463180 (FUN_00463180, ?EnablePrivilege@CDiskWatch@Moho@@ABE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z)
 */
bool CDiskWatch::EnablePrivilege(const msvc8::string& privilegeName, const bool enable) const
{
  HANDLE tokenHandle = nullptr;
  const HANDLE currentProcess = ::GetCurrentProcess();
  if (!::OpenProcessToken(currentProcess, TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
    return false;
  }

  TOKEN_PRIVILEGES newState{};
  newState.PrivilegeCount = 1;
  if (!::LookupPrivilegeValueA(nullptr, privilegeName.c_str(), &newState.Privileges[0].Luid)) {
    (void)::CloseHandle(tokenHandle);
    return false;
  }

  newState.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0u;
  (void)::AdjustTokenPrivileges(tokenHandle, FALSE, &newState, sizeof(newState), nullptr, nullptr);
  const bool success = ::GetLastError() == ERROR_SUCCESS;

  (void)::CloseHandle(tokenHandle);
  return success;
}

/**
 * Address: 0x004629B0 (FUN_004629B0, ?WatchQuery@CDiskWatch@Moho@@QAEXXZ)
 */
void CDiskWatch::WatchQuery()
{
  gpg::core::func_LockShared(&mLock);

  DiskWatchMapNode* const head = mDirWatchMap.mHead;
  if (head != nullptr) {
    for (DiskWatchMapNode* node = head->mLeft; node != nullptr && node != head; node = NextWatchMapNode(node, head)) {
      CDiskDirWatch* const dirWatch = node->mDirWatch;
      if (dirWatch != nullptr) {
        dirWatch->Update();
      }
    }
  }

  gpg::core::func_UnlockShared(&mLock);
}

/**
 * Address: 0x004632B0 (?DISK_AddWatchDirectory@Moho@@YA_NVStrArg@gpg@@@Z)
 */
bool moho::DISK_AddWatchDirectory(const gpg::StrArg directoryPath)
{
  EnsureDiskWatchInitialized();
  if (gDiskWatch == nullptr) {
    return false;
  }

  return gDiskWatch->AddDirectory(directoryPath);
}

/**
 * Address: 0x004632E0 (FUN_004632E0, ?DISK_RemoveWatchDirectory@Moho@@YA_NVStrArg@gpg@@@Z)
 */
bool moho::DISK_RemoveWatchDirectory(const gpg::StrArg directoryPath)
{
  EnsureDiskWatchInitialized();
  if (gDiskWatch == nullptr) {
    return false;
  }

  return gDiskWatch->RemoveDirectoryW(directoryPath);
}

/**
 * Address: 0x00463310 (?DISK_AddWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
 */
void moho::DISK_AddWatchListener(CDiskWatchListener* const listener)
{
  if (listener == nullptr) {
    return;
  }

  EnsureDiskWatchInitialized();
  gDiskWatch->AddListener(listener);
}

/**
 * Address: 0x00463340 (?DISK_RemoveWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
 */
void moho::DISK_RemoveWatchListener(CDiskWatchListener* const listener)
{
  if (listener == nullptr) {
    return;
  }

  EnsureDiskWatchInitialized();
  gDiskWatch->RemoveListener(listener);
}

/**
 * Address: 0x004633A0 (FUN_004633A0, ?DISK_UpdateWatcher@Moho@@YAXXZ)
 */
void moho::DISK_UpdateWatcher()
{
  EnsureDiskWatchInitialized();
  if (gDiskWatch != nullptr) {
    gDiskWatch->WatchQuery();
  }
}

/**
 * Address: 0x004633D0 (?DISK_ResetWatch@Moho@@YAXXZ)
 */
void moho::DISK_ResetWatch()
{
  std::lock_guard<std::mutex> lock(gDiskWatchInitMutex);
  delete gDiskWatch;
  gDiskWatch = nullptr;
}
