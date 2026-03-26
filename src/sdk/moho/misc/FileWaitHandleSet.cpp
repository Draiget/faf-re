#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/CZipFile.h"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <stdexcept>
#include <string_view>

#include "gpg/core/streams/FileStream.h"

namespace
{
  moho::FWaitHandleSet sFWaitHandleSet{};
  moho::FWaitHandleSet* sPFWaitHandleSet = nullptr;
  std::once_flag sFileWaitHandleSetInitOnce;

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

  class ScopedWaitNotify
  {
  public:
    explicit ScopedWaitNotify(moho::FWaitHandleSet& waitHandleSet)
      : mWaitHandleSet(waitHandleSet)
    {
    }

    ~ScopedWaitNotify()
    {
      if (mShouldNotify) {
        mWaitHandleSet.Notify();
      }
    }

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

    waitHandleSet.Wait();
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

    delete nodeToErase;
    if (map.mSize != 0) {
      --map.mSize;
    }
    ZipMapRebuildHeadLinks(map);
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

  void ResetFileWaitHandleSetPointer()
  {
    sPFWaitHandleSet = nullptr;
  }

  /**
   * Address: 0x00BEF5A0 (FUN_00BEF5A0, sub_BEF5A0)
   *
   * What it does:
   * `atexit` hook that resets the published global file wait-handle pointer.
   */
  void FileWaitHandleSetAtProcessExit()
  {
    ResetFileWaitHandleSetPointer();
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
  sFWaitHandleSet.mLockLevel = 0;
  sFWaitHandleSet.mWaitingLevel = 0;
  sFWaitHandleSet.mIsLocked = 0;
  sFWaitHandleSet.mPrev = reinterpret_cast<SFileWaitHandle*>(&sFWaitHandleSet.mPrev);
  sFWaitHandleSet.mNext = reinterpret_cast<SFileWaitHandle*>(&sFWaitHandleSet.mPrev);
  sFWaitHandleSet.mZipEntries = {};
  sFWaitHandleSet.mFileInfo = {};
  sFWaitHandleSet.mHandle = nullptr;
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
 * Address: 0x00413F90 (FUN_00413F90, Moho::FWaitHandleSet::Wait)
 *
 * What it does:
 * Acquires one shared read lane for wait-handle state and waits while an
 * exclusive locker or queued lock waiters are active.
 */
void moho::FWaitHandleSet::Wait()
{
  boost::mutex::scoped_lock guard(mLock.mMutex);
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
  boost::mutex::scoped_lock guard(mLock.mMutex);
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
  boost::mutex::scoped_lock guard(mLock.mMutex);
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
  boost::mutex::scoped_lock guard(mLock.mMutex);
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
    return handle != nullptr;
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
  if (outInfo != nullptr) {
    *outInfo = diskInfo;
  }
  return queryOk && HasWriteTime(diskInfo);
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
