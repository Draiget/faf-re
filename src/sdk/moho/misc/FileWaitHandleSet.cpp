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
  using DiskThreadStateStringMap = std::unordered_map<const moho::FWHSThreadStateRuntime*, msvc8::string*>;

  /**
   * Per-thread error-string storage, standing in for the
   * `boost::thread_specific_ptr` the binary keeps in `FWHSThreadStateRuntime`.
   *
   * The map is allocated once per thread and deliberately never destroyed.
   * FileWaitHandleSetAtProcessExit is an atexit handler, and MSVC runs those
   * after the primary thread's thread_local destructors, so a plain
   * `thread_local` map was already gone by the time the handler reached in to
   * release its entry - the find faulted inside _Find_last on freed bucket
   * storage. A TSS slot has the same lifetime shape: it outlives everything
   * that reads it, and its contents go with the process.
   */
  [[nodiscard]] DiskThreadStateStringMap& DiskThreadStateStrings()
  {
    static thread_local auto* const strings = new DiskThreadStateStringMap();
    return *strings;
  }
  constexpr const char* kDiskFindFilesHelpText =
    "files = DiskFindFiles(directory, pattern)\nreturns a list of files in a directory";
  constexpr const char* kDiskGetFileInfoHelpText =
    "info = DiskGetFileInfo(filename)\n"
    "returns a table describing the given file, or false if the file doesn't exist.\n"
    "    info.IsFolder -- true if the filename refers to a folder\n"
    "    info.IsReadOnly -- true if file is read-only\n"
    "    info.SizeBytes -- size of file in bytes\n"
    "    info.LastWriteTime -- timestamp of last write to file";
  constexpr const char* kDiskToLocalHelpText = "localPath = DiskToLocal(SysOrLocalPath)\n"
                                               "Converts a system path to a local path. Leaves\n"
                                               "path alone if already local.";
  constexpr const char* kBasenameHelpText =
    "base = Basename(fullPath,stripExtension?) -- return the last component of a path";
  constexpr const char* kDirnameHelpText = "base = Dirname(fullPath) -- return a path with trailing filename removed";
  constexpr const char* kFileCollapsePathHelpText =
    "path = FileCollapsePath(fullPath) -- collapse out any intermediate /./ or /../ directory names from a path";

  [[nodiscard]] moho::CScrLuaInitFormSet& CoreLuaInitSet()
  {
    // Every file that wants this set must resolve the one that already
    // exists. Declaring a fresh static here creates a second set with the
    // same name, and SCR_FindLuaInitFormSet returns only the first - so
    // half the binders never get run.
    if (moho::CScrLuaInitFormSet* const existing = moho::SCR_FindLuaInitFormSet("Core"); existing != nullptr) {
      return *existing;
    }

    static moho::CScrLuaInitFormSet sSet("Core");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(
    lua_State* const luaContext
  ) noexcept
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
  void CreateDiskThreadStateRuntime(
    moho::FWHSThreadStateRuntime& runtime
  )
  {
    runtime.mTss = &runtime;
  }

  /**
   * Address: 0x0045C110 (FUN_0045C110, onExit)
   *
   * What it does:
   * Releases one heap-allocated disk thread-state error string value.
   */
  void DestroyDiskThreadStateString(
    msvc8::string* const value
  )
  {
    delete value;
  }

  void CleanupDiskThreadStateValue(
    const moho::FWHSThreadStateRuntime& runtime
  )
  {
    const auto it = DiskThreadStateStrings().find(&runtime);
    if (it != DiskThreadStateStrings().end()) {
      DestroyDiskThreadStateString(it->second);
      DiskThreadStateStrings().erase(it);
    }
  }

  [[nodiscard]]
  msvc8::string* GetOrCreateDiskThreadStateValue(
    moho::FWHSThreadStateRuntime& runtime
  )
  {
    if (msvc8::string*& slot = DiskThreadStateStrings()[&runtime]; slot == nullptr) {
      slot = new msvc8::string();
    }
    return DiskThreadStateStrings()[&runtime];
  }

  /**
   * Address: 0x00456B40 (FUN_00456B40, sub_456B40)
   *
   * What it does:
   * Creates one nested `Flags` table, stores it under the owner table at
   * `ownerTableIndex`, and returns a stack view for the nested table.
   */
  [[nodiscard]] LuaPlus::LuaStackObject CreateFlagsTableStackObject(
    LuaPlus::LuaState* const state,
    const int ownerTableIndex
  )
  {
    lua_newtable(state->m_state);
    lua_pushstring(state->m_state, "Flags");
    lua_pushvalue(state->m_state, lua_gettop(state->m_state) - 1);
    lua_settable(state->m_state, ownerTableIndex);
    return LuaPlus::LuaStackObject(state, lua_gettop(state->m_state));
  }

  boost::mutex& EnsureFileWaitSetMutex(
    moho::FWHSLockRuntime& lockRuntime
  )
  {
    if (lockRuntime.mMutex == nullptr) {
      lockRuntime.mMutex = new boost::mutex();
    }
    return *lockRuntime.mMutex;
  }

  /**
   * Address: 0x0045F260 (FUN_0045F260, sub_45F260)
   *
   * What it does:
   * Allocates raw storage for one-or-more zip-entry map nodes with overflow
   * guard semantics.
   */
  /**
   * Address: 0x0045DD80 (FUN_0045DD80)
   *
   * What it does:
   * Tail-thunk adapter that forwards one single-node zip-entry allocation
   * lane into `FUN_0045F260`.
   */
  [[maybe_unused]]
  /**
   * Address: 0x0045F380 (FUN_0045F380, sub_45F380)
   *
   * What it does:
   * Allocates raw storage for one-or-more file-info map nodes with overflow
   * guard semantics.
   */
  /**
   * Address: 0x0045E320 (FUN_0045E320, sub_45E320)
   *
   * What it does:
   * Allocates raw storage for one file-info map node.
   */
  /**
   * Address: 0x0045C8F0 (FUN_0045C8F0, std::map_string_FWHSEntry::_Lbound)
   *
   * What it does:
   * Returns the first zip-entry node whose key is not less than the canonical
   * path.
   */
  /**
   * Address: 0x0045AF50 (FUN_0045AF50, std::map_string_FWHSEntry::find)
   *
   * What it does:
   * Finds one exact canonical-path match in the zip-entry map and returns the
   * map head sentinel when not found.
   */
  /**
   * Address: 0x0045D080 (FUN_0045D080, std::map_string_SDiskFileInfo::_Lbound)
   *
   * What it does:
   * Returns the first file-info node whose key is not less than the canonical
   * path.
   */
  /**
   * Address: 0x0045B160 (FUN_0045B160, std::map_string_SDiskFileInfo::find)
   *
   * What it does:
   * Finds one exact canonical-path match in the file-info map and returns the
   * map head sentinel when not found.
   */
  /**
   * Address: 0x0045DFA0 (FUN_0045DFA0, sub_45DFA0)
   *
   * What it does:
   * Allocates and initializes one file-info map node for insertion.
   */
  /**
   * Address: 0x0045DF60 (FUN_0045DF60, sub_45DF60)
   *
   * What it does:
   * Allocates and initializes one file-info map head/sentinel node.
   */
  /**
   * Address: 0x0045DE90 (FUN_0045DE90, sub_45DE90)
   *
   * What it does:
   * Returns the left-most descendant from one file-info tree node.
   */
  /**
   * Address: 0x0045DE70 (FUN_0045DE70, sub_45DE70)
   *
   * What it does:
   * Returns the right-most descendant from one file-info tree node.
   */
  /**
   * Address: 0x0045E3A0 (FUN_0045E3A0, sub_45E3A0)
   *
   * What it does:
   * Moves one file-info iterator node to its in-order successor.
   */
  /**
   * Address: 0x0045E340 (FUN_0045E340, sub_45E340)
   *
   * What it does:
   * Moves one file-info iterator node to its in-order predecessor.
   */
  /**
   * Address: 0x0045DF10 (FUN_0045DF10, std::map_string_SDiskFileInfo::upper_bound)
   *
   * What it does:
   * Returns the first file-info node whose key is greater than the canonical
   * path.
   */
  /**
   * Address: 0x0045AFE0 (FUN_0045AFE0, std::map_string_SDiskFileInfo::operator[])
   *
   * What it does:
   * Finds or creates one file-info cache record for the canonical path and
   * returns a typed reference to the value payload.
   */
  /**
   * Address: 0x0045B100 (FUN_0045B100, std::map_string_SDiskFileInfo::erase)
   *
   * What it does:
   * Removes file-info cache nodes for one canonical key and returns the number
   * of erased nodes.
   */
  [[nodiscard]]
  bool HasWriteTime(
    const moho::SDiskFileInfo& info
  )
  {
    return info.mLastWriteTime.dwLowDateTime != 0 || info.mLastWriteTime.dwHighDateTime != 0;
  }

  [[nodiscard]]
  moho::EFileAttributes BuildFileAttributesFromWin32(
    const DWORD win32Attributes
  )
  {
    const std::uint32_t readonlyFlag = (win32Attributes & FILE_ATTRIBUTE_READONLY) != 0 ? moho::FA_Readonly : 0u;
    const std::uint32_t directoryFlag = (win32Attributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? moho::FA_Directory : 0u;
    return static_cast<moho::EFileAttributes>(readonlyFlag | directoryFlag);
  }

  [[nodiscard]]
  bool TryQueryFileAttributes(
    const msvc8::string& canonicalPath,
    moho::SDiskFileInfo* const outInfo
  )
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

  void AddWaitHandleReference(
    moho::SFileWaitHandle* const handle
  )
  {
    if (handle != nullptr) {
      (void)::InterlockedExchangeAdd(&handle->mLock, 1);
    }
  }

  void ReleaseWaitHandleReference(
    moho::SFileWaitHandle* const handle
  )
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

  void UnmapFileView(
    const char* const mappedView
  )
  {
    if (mappedView != nullptr) {
      (void)::UnmapViewOfFile(mappedView);
    }
  }

  void SetWaitHandleErrorString(
    moho::FWaitHandleSet* const waitHandleSet,
    const msvc8::string& errorText
  )
  {
    if (waitHandleSet == nullptr) {
      return;
    }

    if (msvc8::string* const errorSlot = waitHandleSet->ErrorString(); errorSlot != nullptr) {
      errorSlot->assign_owned(errorText.view());
    }
  }

  void SetWaitHandleErrorFromWin32(
    moho::FWaitHandleSet* const waitHandleSet
  )
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
    explicit ScopedWaitNotify(
      moho::FWaitHandleSet& waitHandleSet
    )
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
    explicit ScopedHandleRef(
      moho::SFileWaitHandle* const handle
    )
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
    moho::FWaitHandleSet& waitHandleSet,
    const gpg::StrArg sourcePath
  )
  {
    msvc8::string canonicalPath{};
    gpg::STR_CanonizeFilename(&canonicalPath, sourcePath != nullptr ? sourcePath : "");

    ScopedWaitNotify notifyGuard(waitHandleSet);

    const moho::FWHSZipEntryMap::iterator zipEntry = waitHandleSet.mZipEntries.find(canonicalPath);
    if (zipEntry != waitHandleSet.mZipEntries.end()) {
      moho::SFileWaitHandle* const handle = zipEntry->second.mHandle;
      const std::uint32_t zipEntryIndex = zipEntry->second.mZipEntryIndex;
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

  /**
   * Address: 0x0045E080 (FUN_0045E080, sub_45E080)
   *
   * What it does:
   * Moves one zip-map iterator node to its in-order predecessor.
   */
  /**
   * Address: 0x0045D170 (FUN_0045D170, std::map_string_FWHSEntry::Iterator::inc)
   *
   * What it does:
   * Advances one zip-map node iterator to its in-order successor.
   */
  /**
   * Address context:
   * - 0x0045E1B0 (FUN_0045E1B0, sub_45E1B0) shared node initializer lane.
   * - 0x0045C940 (FUN_0045C940, sub_45C940) allocator wrapper.
   *
   * What it does:
   * Allocates and initializes one zip-entry map node for insertion.
   */
  /**
   * Address: 0x0045DD20 (FUN_0045DD20, sub_45DD20)
   *
   * What it does:
   * Allocates and initializes one zip-entry map head/sentinel node.
   */
  /**
   * Address: 0x0045C800 (FUN_0045C800, sub_45C800)
   *
   * What it does:
   * Erases one half-open zip-map iterator range `[first, last)` and returns
   * the first iterator not erased.
   */
  /**
   * Every entry the given archive contributed to the mounted-file index.
   *
   * The map is keyed on the path, not on the handle, so unmounting scans it -
   * which is what the binary does too: `RemoveEntry` and `MountZipFile`'s
   * failure path both walk from the leftmost node and erase the first match,
   * over and over, until the walk comes back empty.
   */
  [[nodiscard]]
  moho::FWHSZipEntryMap::iterator FindZipEntryByHandle(
    moho::FWHSZipEntryMap& zipEntries,
    const moho::SFileWaitHandle* const handle
  )
  {
    for (moho::FWHSZipEntryMap::iterator it = zipEntries.begin(); it != zipEntries.end(); ++it) {
      if (it->second.mHandle == handle) {
        return it;
      }
    }
    return zipEntries.end();
  }

  [[nodiscard]]
  moho::SFileWaitHandle* WaitHandleListSentinel(
    moho::FWaitHandleSet& waitHandleSet
  )
  {
    return reinterpret_cast<moho::SFileWaitHandle*>(&waitHandleSet.mPrev);
  }

  [[nodiscard]]
  moho::SFileWaitHandle* FindMountedZipHandleByCanonicalPath(
    moho::FWaitHandleSet& waitHandleSet,
    const msvc8::string& canonicalPath
  )
  {
    moho::SFileWaitHandle* const sentinel = WaitHandleListSentinel(waitHandleSet);
    for (moho::SFileWaitHandle* node = waitHandleSet.mNext; node != sentinel; node = node->mNext) {
      const moho::CZipFile* const zipFile = node != nullptr ? node->mZipFile : nullptr;
      if (zipFile != nullptr && zipFile->mPath == canonicalPath) {
        return node;
      }
    }
    return nullptr;
  }

  void LinkMountedZipHandle(
    moho::FWaitHandleSet& waitHandleSet,
    moho::SFileWaitHandle* const handle
  )
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
  moho::SFileWaitHandle* MountZipFile(
    moho::FWaitHandleSet& waitHandleSet,
    const gpg::StrArg sourcePath
  )
  {
    msvc8::string canonicalPath{};
    gpg::STR_CanonizeFilename(&canonicalPath, sourcePath != nullptr ? sourcePath : "");

    waitHandleSet.Lock();
    if (
      moho::SFileWaitHandle* const existingHandle = FindMountedZipHandleByCanonicalPath(waitHandleSet, canonicalPath);
      existingHandle != nullptr
    ) {
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
    if (
      moho::SFileWaitHandle* const existingHandle = FindMountedZipHandleByCanonicalPath(waitHandleSet, canonicalPath);
      existingHandle != nullptr
    ) {
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

        (void)waitHandleSet.mZipEntries.insert(
          {mountedEntryPath, moho::FWHSEntry{mountedHandle.get(), static_cast<std::uint32_t>(entryIndex)}}
        );
      }
    } catch (...) {
      while (true) {
        const moho::FWHSZipEntryMap::iterator danglingEntry =
          FindZipEntryByHandle(waitHandleSet.mZipEntries, mountedHandle.get());
        if (danglingEntry == waitHandleSet.mZipEntries.end()) {
          break;
        }
        (void)waitHandleSet.mZipEntries.erase(danglingEntry);
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

  void ReleaseWaitHandleSetVfs(
    moho::FWaitHandleSet& waitHandleSet
  )
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
  void ReleaseWaitHandleThreadStateRuntime(
    moho::FWHSThreadStateRuntime& runtime
  )
  {
    CleanupDiskThreadStateValue(runtime);
    runtime.mTss = nullptr;
  }

  void UnlinkWaitHandleSetSentinel(
    moho::FWaitHandleSet& waitHandleSet
  )
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
  moho::FWaitHandleSet* InitializeStaticFileWaitHandleSet(
    moho::FWaitHandleSet& waitHandleSet
  )
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
  void DestroyStaticFileWaitHandleSet(
    moho::FWaitHandleSet& waitHandleSet
  )
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

    // The two map teardowns the binary runs between here and the sentinel
    // unlink are `~map()` on `sFWaitHandleSet`'s own members. MSVC emits them
    // for a file-static; naming them here would free the same headers twice.
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
  sFWaitHandleSet.mZipEntries.clear();
  sFWaitHandleSet.mFileInfo.clear();
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
msvc8::auto_ptr<gpg::Stream> moho::DISK_OpenFileRead(
  const gpg::StrArg sourcePath
)
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
msvc8::auto_ptr<gpg::Stream> moho::DISK_OpenFileWrite(
  const gpg::StrArg sourcePath
)
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
moho::SFileWaitHandle* moho::DISK_MountZipFile(
  const gpg::StrArg sourcePath
)
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
bool moho::DISK_GetFileInfo(
  const gpg::StrArg sourcePath,
  SDiskFileInfo* const outInfo,
  const bool realOnly
)
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
gpg::MemBuffer<char> moho::DISK_ReadFile(
  const gpg::StrArg sourcePath
)
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
gpg::MemBuffer<const char> moho::DISK_MemoryMapFile(
  const gpg::StrArg sourcePath
)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return {};
  }

  return sPFWaitHandleSet->MemoryMapFile(sourcePath);
}

/**
 * Address: 0x00459D50 (FUN_00459D50,
 * ?DISK_GetLastError@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ)
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
 * Installs the mounted virtual file system, returning the previous one.
 *
 * See the header for why this exists: the binary performs this store inline in
 * DISK_SetupDataAndSearchPaths, where the wait-handle set is in reach.
 */
moho::CVirtualFileSystem* moho::DISK_ExchangeVFS(CVirtualFileSystem* const virtualFileSystem)
{
  FILE_EnsureWaitHandleSet();
  if (sPFWaitHandleSet == nullptr) {
    return nullptr;
  }

  CVirtualFileSystem* const previous = sPFWaitHandleSet->mHandle;
  sPFWaitHandleSet->mHandle = virtualFileSystem;
  return previous;
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
void moho::DISK_InvalidateFileInfoCache(
  const gpg::StrArg sourcePath
)
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
int moho::cfunc_DiskFindFiles(
  lua_State* const luaContext
)
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
int moho::cfunc_DiskFindFilesL(
  LuaPlus::LuaState* const state
)
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
    CoreLuaInitSet(), "DiskFindFiles", &moho::cfunc_DiskFindFiles, nullptr, "<global>", kDiskFindFilesHelpText
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
int moho::cfunc_DiskGetFileInfo(
  lua_State* const luaContext
)
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
int moho::cfunc_DiskGetFileInfoL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kDiskGetFileInfoHelpText, 1, argumentCount);
  }

  FILE_EnsureWaitHandleSet();
  CVirtualFileSystem* const vfs = sPFWaitHandleSet->mHandle;

  LuaPlus::LuaStackObject filenameArg(state, 1);
  const char* const filename = lua_tostring(state->m_state, 1);
  if (filename == nullptr) {
    filenameArg.TypeError("string");

    // Added manually, not from original binary recovery: protect against nil filename input.
    // Fixes: https://github.com/FAForever/FA-Binary-Patches/issues/125
    lua_pushboolean(state->m_state, 0);
    (void)lua_gettop(state->m_state);
    return 1;
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
    CoreLuaInitSet(), "DiskGetFileInfo", &moho::cfunc_DiskGetFileInfo, nullptr, "<global>", kDiskGetFileInfoHelpText
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
int moho::cfunc_DiskToLocal(
  lua_State* const luaContext
)
{
  return cfunc_DiskToLocalL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004571E0 (FUN_004571E0, cfunc_DiskToLocalL)
 *
 * What it does:
 * Converts one system path to mounted/local VFS path form.
 */
int moho::cfunc_DiskToLocalL(
  LuaPlus::LuaState* const state
)
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
    CoreLuaInitSet(), "DiskToLocal", &moho::cfunc_DiskToLocal, nullptr, "<global>", kDiskToLocalHelpText
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
int moho::cfunc_Basename(
  lua_State* const luaContext
)
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
int moho::cfunc_BasenameL(
  LuaPlus::LuaState* const state
)
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
    CoreLuaInitSet(), "Basename", &moho::cfunc_Basename, nullptr, "<global>", kBasenameHelpText
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
int moho::cfunc_Dirname(
  lua_State* const luaContext
)
{
  return cfunc_DirnameL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x004574E0 (FUN_004574E0, cfunc_DirnameL)
 *
 * What it does:
 * Returns one path with trailing filename removed.
 */
int moho::cfunc_DirnameL(
  LuaPlus::LuaState* const state
)
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
  static CScrLuaBinder binder(CoreLuaInitSet(), "Dirname", &moho::cfunc_Dirname, nullptr, "<global>", kDirnameHelpText);
  return &binder;
}

/**
 * Address: 0x004575C0 (FUN_004575C0, cfunc_FileCollapsePath)
 *
 * What it does:
 * Lua callback thunk that unwraps `lua_State*` and forwards to
 * `cfunc_FileCollapsePathL`.
 */
int moho::cfunc_FileCollapsePath(
  lua_State* const luaContext
)
{
  return cfunc_FileCollapsePathL(ResolveBindingState(luaContext));
}

/**
 * Address: 0x00457640 (FUN_00457640, cfunc_FileCollapsePathL)
 *
 * What it does:
 * Collapses one path (`/./`, `/../`) and returns `(collapsedPath, success)`.
 */
int moho::cfunc_FileCollapsePathL(
  LuaPlus::LuaState* const state
)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kFileCollapsePathHelpText, 1, argumentCount);
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
    CoreLuaInitSet(), "FileCollapsePath", &moho::cfunc_FileCollapsePath, nullptr, "<global>", kFileCollapsePathHelpText
  );
  return &binder;
}

/**
 * Address: 0x00BC45C0 (FUN_00BC45C0, register_DiskFindFiles_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_DiskFindFiles_LuaFuncDef()
{
  return func_DiskFindFiles_LuaFuncDef();
}

/**
 * Address: 0x00BC45D0 (FUN_00BC45D0, register_DiskGetFileInfo_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_DiskGetFileInfo_LuaFuncDef()
{
  return func_DiskGetFileInfo_LuaFuncDef();
}

/**
 * Address: 0x00BC45E0 (FUN_00BC45E0, register_DiskToLocal_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_DiskToLocal_LuaFuncDef()
{
  return func_DiskToLocal_LuaFuncDef();
}

/**
 * Address: 0x00BC45F0 (FUN_00BC45F0, register_Basename_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_Basename_LuaFuncDef()
{
  return func_Basename_LuaFuncDef();
}

/**
 * Address: 0x00BC4600 (FUN_00BC4600, register_Dirname_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_Dirname_LuaFuncDef()
{
  return func_Dirname_LuaFuncDef();
}

/**
 * Address: 0x00BC4610 (FUN_00BC4610, register_FileCollapsePath_LuaFuncDef)
 */
moho::CScrLuaInitForm* moho::register_FileCollapsePath_LuaFuncDef()
{
  return func_FileCollapsePath_LuaFuncDef();
}

namespace
{
  /**
   * Runs this file's registration thunks at static-init time, which is where
   * the binary drives them from (the CRT initialiser array).
   *
   * They were defined and never called, so the binders never joined their
   * init-form set and these globals did not exist in any Lua state. The
   * damage was not a missing function - FAF's /lua/system/config.lua puts an
   * __index on _G that raises on any nonexistent global, and that handler
   * itself calls repr(), which globalInit only defines a file later. So the
   * first missing global sent __index into unbounded recursion and killed the
   * whole bootstrap with a C stack overflow.
   */
  struct FileWaitHandleSetLuaFunctionBootstrap
  {
    FileWaitHandleSetLuaFunctionBootstrap()
    {
      (void)moho::register_DiskFindFiles_LuaFuncDef();
      (void)moho::register_DiskGetFileInfo_LuaFuncDef();
      (void)moho::register_DiskToLocal_LuaFuncDef();
      (void)moho::register_Basename_LuaFuncDef();
      (void)moho::register_Dirname_LuaFuncDef();
      (void)moho::register_FileCollapsePath_LuaFuncDef();
    }
  };

  const FileWaitHandleSetLuaFunctionBootstrap gFileWaitHandleSetLuaFunctionBootstrap{};
} // namespace


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
 * Address: 0x00458CC0 (FUN_00458CC0, ??1FWHSZipFile@Moho@@QAE@XZ)
 * Mangled: ??1FWHSZipFile@Moho@@QAE@XZ
 *
 * IDA signature:
 * void __stdcall Moho::FWHSZipFile::~FWHSZipFile(Moho::SFileWaitHandle* this);
 *
 * What it does:
 * Closes the owned zip file, then unlinks this handle from the active-handle
 * ring and re-points both of its links at itself so the detached node stays a
 * valid one-element ring.
 */
moho::SFileWaitHandle::~SFileWaitHandle()
{
  delete mZipFile;

  mNext->mPrev = mPrev;
  mPrev->mNext = mNext;
  mNext = this;
  mPrev = this;
}

/**
 * Address: 0x00458BC0 (FUN_00458BC0, Moho::FWaitHandleSet::RemoveEntry)
 *
 * What it does:
 * Unlinks one zip wait-handle entry from the active-handle list, erases all
 * matching zip-map nodes, and destroys the detached handle object.
 */
void moho::FWaitHandleSet::RemoveEntry(
  SFileWaitHandle* const handle
)
{
  if (handle == nullptr) {
    return;
  }

  Lock();
  if (handle->mLock != 0) {
    NotifyAll();
    return;
  }

  // The handle stays linked into the ring until `delete handle` below runs
  // `~SFileWaitHandle`, which is what unlinks it. Anything woken by the
  // NotifyAll at the end of this function still sees it on the ring.
  while (true) {
    const FWHSZipEntryMap::iterator entryToErase = FindZipEntryByHandle(mZipEntries, handle);
    if (entryToErase == mZipEntries.end()) {
      break;
    }
    (void)mZipEntries.erase(entryToErase);
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
bool moho::FWaitHandleSet::GetFileInfo(
  const gpg::StrArg sourcePath,
  SDiskFileInfo* const outInfo,
  const bool realOnly
)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return false;
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  Wait();
  const FWHSZipEntryMap::iterator zipEntry = mZipEntries.find(canonicalPath);
  if (zipEntry != mZipEntries.end()) {
    SFileWaitHandle* const handle = zipEntry->second.mHandle;
    CZipFile* const zipFile = handle != nullptr ? handle->mZipFile : nullptr;
    const std::uint32_t zipEntryIndex = zipEntry->second.mZipEntryIndex;
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

  const FWHSFileInfoMap::iterator cachedInfo = mFileInfo.find(canonicalPath);
  if (cachedInfo != mFileInfo.end()) {
    if (outInfo != nullptr) {
      *outInfo = cachedInfo->second;
    }
    const bool hasCachedWriteTime = HasWriteTime(cachedInfo->second);
    Notify();
    return hasCachedWriteTime;
  }

  Notify();

  SDiskFileInfo diskInfo{};
  const bool queryOk = TryQueryFileAttributes(canonicalPath, &diskInfo);
  if (queryOk) {
    Lock();
    mFileInfo[canonicalPath] = diskInfo;
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
gpg::MemBuffer<char> moho::FWaitHandleSet::ReadFile(
  const gpg::StrArg sourcePath
)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return {};
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  ScopedWaitNotify notifyGuard(*this);

  const FWHSZipEntryMap::iterator zipEntry = mZipEntries.find(canonicalPath);
  if (zipEntry != mZipEntries.end() && zipEntry->second.mHandle != nullptr) {
    SFileWaitHandle* const handle = zipEntry->second.mHandle;
    const std::uint32_t zipEntryIndex = zipEntry->second.mZipEntryIndex;
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
    sourcePathWide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
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
gpg::MemBuffer<const char> moho::FWaitHandleSet::MemoryMapFile(
  const gpg::StrArg sourcePath
)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return {};
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  ScopedWaitNotify notifyGuard(*this);

  const FWHSZipEntryMap::iterator zipEntry = mZipEntries.find(canonicalPath);
  if (zipEntry != mZipEntries.end() && zipEntry->second.mHandle != nullptr) {
    SFileWaitHandle* const handle = zipEntry->second.mHandle;
    const std::uint32_t zipEntryIndex = zipEntry->second.mZipEntryIndex;
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
    sourcePathWide.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
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
void moho::FWaitHandleSet::InvalidateFileInfoCache(
  const gpg::StrArg sourcePath
)
{
  if (sourcePath == nullptr || sourcePath[0] == '\0') {
    return;
  }

  msvc8::string canonicalPath{};
  gpg::STR_CanonizeFilename(&canonicalPath, sourcePath);

  Lock();
  (void)mFileInfo.erase(canonicalPath);
  NotifyAll();
}

/**
  * Alias of FUN_00458D30 (non-canonical helper lane).
 *
 * What it does:
 * Resolves file metadata through the wait-handle/VFS runtime when available.
 * The recovered `realOnly` gate is preserved for callsite parity.
 */
bool moho::FILE_GetFileInfo(
  const gpg::StrArg sourcePath,
  SDiskFileInfo* const outInfo,
  const bool realOnly
)
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

msvc8::string* moho::FILE_ToMountedPath(
  msvc8::string* const outPath,
  const gpg::StrArg sourcePath
)
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
