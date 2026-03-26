#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

#include "boost/condition.h"
#include "boost/mutex.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/Stream.h"
#include "legacy/containers/AutoPtr.h"
#include "moho/misc/CVirtualFileSystem.h"

namespace moho
{
  class CZipFile;

  enum EFileAttributes : std::uint32_t
  {
    FA_None = 0,
    FA_Directory = 1,
    FA_Readonly = 2,
    FA_Zipped = 4,
  };

  struct SDiskFileInfo
  {
    EFileAttributes mFileAttributes = FA_None; // +0x00
    std::uint32_t mFileSize = 0;               // +0x04
    FILETIME mLastWriteTime{};                 // +0x08
  };

  static_assert(sizeof(SDiskFileInfo) == 0x10, "SDiskFileInfo size must be 0x10");

  struct SFileWaitHandle
  {
    SFileWaitHandle* mNext = this; // +0x00
    SFileWaitHandle* mPrev = this; // +0x04
    volatile long mLock = 0;       // +0x08
    CZipFile* mZipFile = nullptr;  // +0x0C
  };

  static_assert(sizeof(SFileWaitHandle) == 0x10, "SFileWaitHandle size must be 0x10");

  using FWHSZipFile = SFileWaitHandle;

  struct FWHSEntry
  {
    SFileWaitHandle* mHandle = nullptr;    // +0x00
    std::uint32_t mZipEntryIndex = 0;      // +0x04
  };

  static_assert(sizeof(FWHSEntry) == 0x08, "FWHSEntry size must be 0x08");

  struct FWHSZipEntryMapNode
  {
    FWHSZipEntryMapNode* mLeft = nullptr;    // +0x00
    FWHSZipEntryMapNode* mParent = nullptr;  // +0x04
    FWHSZipEntryMapNode* mRight = nullptr;   // +0x08
    msvc8::string mCanonicalPath{};          // +0x0C
    FWHSEntry mEntry{};                      // +0x28
    std::uint8_t mColor = 0;                 // +0x30
    std::uint8_t mIsNil = 0;                 // +0x31
    std::uint16_t mPadding32 = 0;            // +0x32
  };

  static_assert(offsetof(FWHSZipEntryMapNode, mCanonicalPath) == 0x0C, "FWHSZipEntryMapNode::mCanonicalPath offset must be 0x0C");
  static_assert(offsetof(FWHSZipEntryMapNode, mEntry) == 0x28, "FWHSZipEntryMapNode::mEntry offset must be 0x28");
  static_assert(offsetof(FWHSZipEntryMapNode, mIsNil) == 0x31, "FWHSZipEntryMapNode::mIsNil offset must be 0x31");

  struct FWHSFileInfoMapNode
  {
    FWHSFileInfoMapNode* mLeft = nullptr;    // +0x00
    FWHSFileInfoMapNode* mParent = nullptr;  // +0x04
    FWHSFileInfoMapNode* mRight = nullptr;   // +0x08
    std::uint32_t mUnknown0C = 0;            // +0x0C
    msvc8::string mCanonicalPath{};          // +0x10
    std::uint32_t mUnknown2C = 0;            // +0x2C
    SDiskFileInfo mInfo{};                   // +0x30
    std::uint8_t mColor = 0;                 // +0x40
    std::uint8_t mIsNil = 0;                 // +0x41
    std::uint16_t mPadding42 = 0;            // +0x42
  };

  static_assert(offsetof(FWHSFileInfoMapNode, mCanonicalPath) == 0x10, "FWHSFileInfoMapNode::mCanonicalPath offset must be 0x10");
  static_assert(offsetof(FWHSFileInfoMapNode, mInfo) == 0x30, "FWHSFileInfoMapNode::mInfo offset must be 0x30");
  static_assert(offsetof(FWHSFileInfoMapNode, mIsNil) == 0x41, "FWHSFileInfoMapNode::mIsNil offset must be 0x41");

  template <typename TNode>
  struct FWHSTreeMap
  {
    void* mProxy = nullptr;  // +0x00
    TNode* mHead = nullptr;  // +0x04
    std::uint32_t mSize = 0; // +0x08
  };

  static_assert(sizeof(FWHSTreeMap<FWHSZipEntryMapNode>) == 0x0C, "FWHSTreeMap<FWHSZipEntryMapNode> size must be 0x0C");
  static_assert(sizeof(FWHSTreeMap<FWHSFileInfoMapNode>) == 0x0C, "FWHSTreeMap<FWHSFileInfoMapNode> size must be 0x0C");

  struct FWHSLockRuntime
  {
    boost::mutex mMutex{};           // +0x00
    std::uint8_t mPadding05[3]{};    // +0x05
  };

  static_assert(sizeof(FWHSLockRuntime) == 0x08, "FWHSLockRuntime size must be 0x08");

  /**
   * Address context:
   * - `func_EnsureFileCWaitHandleSet` (`0x00457F90`) publishes the global pointer.
   * - `func_InitFileCWaitHandleSet` (`0x00457FF0`) initializes this object.
   */
  struct FWaitHandleSet
  {
    FWHSLockRuntime mLock{};                          // +0x00
    boost::condition mObjectSender{};                 // +0x08
    std::int32_t mLockLevel = 0;                      // +0x20
    std::int32_t mWaitingLevel = 0;                   // +0x24
    std::uint8_t mIsLocked = 0;                       // +0x28
    std::uint8_t mPadding29[3]{};                     // +0x29
    SFileWaitHandle* mPrev = nullptr;                 // +0x2C
    SFileWaitHandle* mNext = nullptr;                 // +0x30
    FWHSTreeMap<FWHSZipEntryMapNode> mZipEntries{};   // +0x34
    FWHSTreeMap<FWHSFileInfoMapNode> mFileInfo{};     // +0x40
    CVirtualFileSystem* mHandle = nullptr; // +0x4C

    /**
     * Address: 0x00413F90 (FUN_00413F90, Moho::FWaitHandleSet::Wait)
     *
     * What it does:
     * Acquires one shared read lane for wait-handle state and waits while an
     * exclusive locker or queued lock waiters are active.
     */
    void Wait();

    /**
     * Address: 0x00414030 (FUN_00414030, Moho::FWaitHandleSet::Notify)
     *
     * What it does:
     * Releases one shared read lane and wakes queued exclusive waiters when the
     * shared-reader count reaches zero.
     */
    void Notify();

    /**
     * Address: 0x004140A0 (FUN_004140A0, Moho::FWaitHandleSet::Lock)
     *
     * What it does:
     * Acquires the exclusive lock lane, waiting for active readers and any
     * existing exclusive owner to drain.
     */
    void Lock();

    /**
     * Address: 0x00414140 (FUN_00414140, Moho::FWaitHandleSet::NotifyAll)
     *
     * What it does:
     * Releases the exclusive lock lane and wakes all waiters.
     */
    void NotifyAll();

    /**
     * Address: 0x00458BC0 (FUN_00458BC0, Moho::FWaitHandleSet::RemoveEntry)
     *
     * What it does:
     * Unlinks one zip wait-handle entry from the active-handle list, erases
     * matching zip-map records, and destroys the detached handle.
     */
    void RemoveEntry(SFileWaitHandle* handle);

    /**
     * Address: 0x00458D30 (FUN_00458D30, Moho::FWaitHandleSet::GetFileInfo)
     *
     * What it does:
     * Resolves metadata for one canonical path through zip-entry records and the
     * cached file-info map, then falls back to Win32 file attributes.
     */
    bool GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo, bool realOnly);
  };

  static_assert(offsetof(FWaitHandleSet, mLock) == 0x00, "FWaitHandleSet::mLock offset must be 0x00");
  static_assert(offsetof(FWaitHandleSet, mObjectSender) == 0x08, "FWaitHandleSet::mObjectSender offset must be 0x08");
  static_assert(offsetof(FWaitHandleSet, mLockLevel) == 0x20, "FWaitHandleSet::mLockLevel offset must be 0x20");
  static_assert(offsetof(FWaitHandleSet, mWaitingLevel) == 0x24, "FWaitHandleSet::mWaitingLevel offset must be 0x24");
  static_assert(offsetof(FWaitHandleSet, mIsLocked) == 0x28, "FWaitHandleSet::mIsLocked offset must be 0x28");
  static_assert(offsetof(FWaitHandleSet, mPrev) == 0x2C, "FWaitHandleSet::mPrev offset must be 0x2C");
  static_assert(offsetof(FWaitHandleSet, mNext) == 0x30, "FWaitHandleSet::mNext offset must be 0x30");
  static_assert(offsetof(FWaitHandleSet, mZipEntries) == 0x34, "FWaitHandleSet::mZipEntries offset must be 0x34");
  static_assert(offsetof(FWaitHandleSet, mFileInfo) == 0x40, "FWaitHandleSet::mFileInfo offset must be 0x40");
  static_assert(offsetof(FWaitHandleSet, mHandle) == 0x4C, "FWaitHandleSet::mHandle offset must be 0x4C");
  static_assert(sizeof(FWaitHandleSet) == 0x50, "FWaitHandleSet size must be 0x50");

  /**
   * Address: 0x00457FF0 (FUN_00457FF0, func_InitFileCWaitHandleSet)
   *
   * What it does:
   * Initializes process-global file wait-handle runtime storage and publishes
   * the singleton pointer.
   */
  FWaitHandleSet* FILE_InitWaitHandleSet();

  /**
   * Address: 0x00457F90 (FUN_00457F90, func_EnsureFileCWaitHandleSet)
   *
   * What it does:
   * Lazily ensures file wait-handle runtime storage is initialized and
   * globally published.
   */
  void FILE_EnsureWaitHandleSet();

  [[nodiscard]] FWaitHandleSet* FILE_GetWaitHandleSet();

  /**
   * Address: 0x00459C40 (FUN_00459C40, ?DISK_OpenFileRead@Moho@@YA?AV?$auto_ptr@VStream@gpg@@@std@@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Opens one canonicalized file path for read, preferring mounted zip entries
   * from the wait-handle set before falling back to a regular file stream.
   */
  [[nodiscard]] msvc8::auto_ptr<gpg::Stream> DISK_OpenFileRead(gpg::StrArg sourcePath);

  /**
   * Address: 0x00459B90 (FUN_00459B90, ?DISK_OpenFileWrite@Moho@@YA?AV?$auto_ptr@VStream@gpg@@@std@@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Opens one file path for write using the legacy buffered file-stream mode.
   */
  [[nodiscard]] msvc8::auto_ptr<gpg::Stream> DISK_OpenFileWrite(gpg::StrArg sourcePath);

  /**
   * Address: 0x00458D30 (FUN_00458D30, Moho::FWaitHandleSet::GetFileInfo)
   *
   * What it does:
   * Resolves file metadata through the wait-handle/VFS runtime when available.
   * The recovered `realOnly` gate is preserved for callsite parity.
   */
  bool FILE_GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo, bool realOnly);

  msvc8::string* FILE_ToMountedPath(msvc8::string* outPath, gpg::StrArg sourcePath);
} // namespace moho
