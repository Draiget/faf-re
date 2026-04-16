#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>

#include "boost/condition.h"
#include "boost/mutex.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/streams/Stream.h"
#include "legacy/containers/AutoPtr.h"
#include "moho/misc/CVirtualFileSystem.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CZipFile;
  class CScrLuaInitForm;

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
  static_assert(sizeof(FWHSZipEntryMapNode) == 0x34, "FWHSZipEntryMapNode size must be 0x34");

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
    std::uint32_t mUnknown44 = 0;            // +0x44
  };

  static_assert(offsetof(FWHSFileInfoMapNode, mCanonicalPath) == 0x10, "FWHSFileInfoMapNode::mCanonicalPath offset must be 0x10");
  static_assert(offsetof(FWHSFileInfoMapNode, mInfo) == 0x30, "FWHSFileInfoMapNode::mInfo offset must be 0x30");
  static_assert(offsetof(FWHSFileInfoMapNode, mIsNil) == 0x41, "FWHSFileInfoMapNode::mIsNil offset must be 0x41");
  static_assert(offsetof(FWHSFileInfoMapNode, mUnknown44) == 0x44, "FWHSFileInfoMapNode::mUnknown44 offset must be 0x44");
  static_assert(sizeof(FWHSFileInfoMapNode) == 0x48, "FWHSFileInfoMapNode size must be 0x48");

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
    boost::mutex* mMutex = nullptr;   // +0x00 (runtime-owned lock pointer)
    std::uint8_t mPadding04[4]{};     // +0x04
  };

  static_assert(sizeof(FWHSLockRuntime) == 0x08, "FWHSLockRuntime size must be 0x08");

  struct FWHSThreadStateRuntime
  {
    void* mTss = nullptr; // +0x00 (boost tss key runtime lane)
  };

  static_assert(sizeof(FWHSThreadStateRuntime) == 0x04, "FWHSThreadStateRuntime size must be 0x04");

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
    CVirtualFileSystem* mHandle = nullptr;            // +0x4C
    FWHSThreadStateRuntime mThreadStateInd{};         // +0x50

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
       * Address: 0x00458D30 (FUN_00458D30)
     *
     * What it does:
     * Resolves metadata for one canonical path through zip-entry records and the
     * cached file-info map, then falls back to Win32 file attributes.
     */
    bool GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo, bool realOnly);

    /**
     * Address: 0x00459300 (FUN_00459300, Moho::FWaitHandleSet::ReadFile)
     *
     * What it does:
     * Reads one canonicalized file path into an owned mutable memory buffer,
     * preferring mounted zip entries when present.
     */
    [[nodiscard]] gpg::MemBuffer<char> ReadFile(gpg::StrArg sourcePath);

    /**
     * Address: 0x004596C0 (FUN_004596C0, Moho::FWaitHandleSet::MemoryMapFile)
     *
     * What it does:
     * Maps one canonicalized file path into an immutable shared memory view,
     * preferring mounted zip entries when present.
     */
    [[nodiscard]] gpg::MemBuffer<const char> MemoryMapFile(gpg::StrArg sourcePath);

    /**
     * Address: 0x00457F20 (FUN_00457F20, Moho::FWaitHandleSet::ErrorString)
     *
     * What it does:
     * Returns one thread-local error string storage lane for this wait-handle
     * set owner.
     */
    [[nodiscard]] msvc8::string* ErrorString();

    /**
     * Address: 0x00458280 (FUN_00458280, Moho::FWaitHandleSet::GetErrorString)
     *
     * What it does:
     * Returns the process-global wait-handle thread-local error string storage.
     */
    [[nodiscard]] static msvc8::string* GetErrorString();

    /**
     * Address: 0x00459070 (FUN_00459070, Moho::FWaitHandleSet::InvalidateFileInfoCache)
     *
     * What it does:
     * Canonicalizes one source path, acquires the exclusive lock lane, and
     * removes cached file-info records for that key.
     */
    void InvalidateFileInfoCache(gpg::StrArg sourcePath);
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
  static_assert(offsetof(FWaitHandleSet, mThreadStateInd) == 0x50, "FWaitHandleSet::mThreadStateInd offset must be 0x50");
  static_assert(sizeof(FWaitHandleSet) == 0x54, "FWaitHandleSet size must be 0x54");

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

  /**
   * Address: 0x00457ED0 (FUN_00457ED0, Moho::GetFWaitHandleSet)
   *
   * What it does:
   * Returns the process-global wait-handle set after one-time initialization.
   */
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
   * Address: 0x00459AF0 (FUN_00459AF0, ?DISK_MountZipFile@Moho@@YA?AVCDiskMountedZipHandle@1@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Mounts one zip archive into the process wait-handle runtime and returns
   * the intrusive mounted-handle reference.
   */
  [[nodiscard]] SFileWaitHandle* DISK_MountZipFile(gpg::StrArg sourcePath);

  /**
   * Address: 0x00459B30 (FUN_00459B30, ?DISK_GetFileInfo@Moho@@YA_NVStrArg@gpg@@PAUSDiskFileInfo@1@@Z)
   *
   * gpg::StrArg,Moho::SDiskFileInfo *,bool
   *
   * What it does:
   * Forwards metadata lookup to the process wait-handle runtime.
   */
  bool DISK_GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo, bool realOnly);

  /**
   * Address: 0x00459CD0 (FUN_00459CD0, ?DISK_ReadFile@Moho@@YA?AU?$MemBuffer@D@gpg@@VStrArg@3@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Reads one source path into an owned mutable memory buffer through the
   * process wait-handle runtime.
   */
  [[nodiscard]] gpg::MemBuffer<char> DISK_ReadFile(gpg::StrArg sourcePath);

  /**
   * Address: 0x00459D10 (FUN_00459D10, ?DISK_MemoryMapFile@Moho@@YA?AU?$MemBuffer@$$CBD@gpg@@VStrArg@3@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Maps one source path into an immutable shared byte view through the process
   * wait-handle runtime.
   */
  [[nodiscard]] gpg::MemBuffer<const char> DISK_MemoryMapFile(gpg::StrArg sourcePath);

  /**
   * Address: 0x00459D50 (FUN_00459D50, ?DISK_GetLastError@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@XZ)
   *
   * What it does:
   * Returns a copy of the current thread-local disk error text.
   */
  [[nodiscard]] msvc8::string DISK_GetLastError();

  /**
   * Address: 0x00459DC0 (FUN_00459DC0, ?DISK_GetVFS@Moho@@YAPAVCVirtualFileSystem@1@XZ)
   *
   * What it does:
   * Returns the process-global mounted virtual file-system owner pointer.
   */
  [[nodiscard]] CVirtualFileSystem* DISK_GetVFS();

  /**
   * Address: 0x00459B60 (FUN_00459B60, ?DISK_InvalidateFileInfoCache@Moho@@YAXVStrArg@gpg@@@Z)
   *
   * gpg::StrArg
   *
   * What it does:
   * Invalidates one canonical file-info cache entry in the process wait-handle
   * set.
   */
  void DISK_InvalidateFileInfoCache(gpg::StrArg sourcePath);

  /**
   * Address: 0x00456BE0 (FUN_00456BE0, cfunc_DiskFindFiles)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_DiskFindFilesL`.
   */
  int cfunc_DiskFindFiles(lua_State* luaContext);

  /**
   * Address: 0x00456C60 (FUN_00456C60, cfunc_DiskFindFilesL)
   *
   * What it does:
   * Enumerates mounted VFS files matching `(directory, pattern)` and returns
   * a 1-based Lua string array.
   */
  int cfunc_DiskFindFilesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00456C00 (FUN_00456C00, func_DiskFindFiles_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `DiskFindFiles`.
   */
  [[nodiscard]] CScrLuaInitForm* func_DiskFindFiles_LuaFuncDef();

  /**
   * Address: 0x00456E30 (FUN_00456E30, cfunc_DiskGetFileInfo)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_DiskGetFileInfoL`.
   */
  int cfunc_DiskGetFileInfo(lua_State* luaContext);

  /**
   * Address: 0x00456EB0 (FUN_00456EB0, cfunc_DiskGetFileInfoL)
   *
   * What it does:
   * Resolves one mounted file path and returns Lua metadata details or `false`
   * when the file does not exist.
   */
  int cfunc_DiskGetFileInfoL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00456E50 (FUN_00456E50, func_DiskGetFileInfo_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `DiskGetFileInfo`.
   */
  [[nodiscard]] CScrLuaInitForm* func_DiskGetFileInfo_LuaFuncDef();

  /**
   * Address: 0x00457160 (FUN_00457160, cfunc_DiskToLocal)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_DiskToLocalL`.
   */
  int cfunc_DiskToLocal(lua_State* luaContext);

  /**
   * Address: 0x004571E0 (FUN_004571E0, cfunc_DiskToLocalL)
   *
   * What it does:
   * Converts one system path to mounted/local VFS path form.
   */
  int cfunc_DiskToLocalL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00457180 (FUN_00457180, func_DiskToLocal_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `DiskToLocal`.
   */
  [[nodiscard]] CScrLuaInitForm* func_DiskToLocal_LuaFuncDef();

  /**
   * Address: 0x004572E0 (FUN_004572E0, cfunc_Basename)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_BasenameL`.
   */
  int cfunc_Basename(lua_State* luaContext);

  /**
   * Address: 0x00457360 (FUN_00457360, cfunc_BasenameL)
   *
   * What it does:
   * Returns the last path component for one input path, with optional
   * extension stripping.
   */
  int cfunc_BasenameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00457300 (FUN_00457300, func_Basename_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `Basename`.
   */
  [[nodiscard]] CScrLuaInitForm* func_Basename_LuaFuncDef();

  /**
   * Address: 0x00457460 (FUN_00457460, cfunc_Dirname)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_DirnameL`.
   */
  int cfunc_Dirname(lua_State* luaContext);

  /**
   * Address: 0x004574E0 (FUN_004574E0, cfunc_DirnameL)
   *
   * What it does:
   * Returns one path with trailing filename removed.
   */
  int cfunc_DirnameL(LuaPlus::LuaState* state);

  /**
   * Address: 0x00457480 (FUN_00457480, func_Dirname_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `Dirname`.
   */
  [[nodiscard]] CScrLuaInitForm* func_Dirname_LuaFuncDef();

  /**
   * Address: 0x004575C0 (FUN_004575C0, cfunc_FileCollapsePath)
   *
   * What it does:
   * Lua callback thunk that unwraps `lua_State*` and forwards to
   * `cfunc_FileCollapsePathL`.
   */
  int cfunc_FileCollapsePath(lua_State* luaContext);

  /**
   * Address: 0x00457640 (FUN_00457640, cfunc_FileCollapsePathL)
   *
   * What it does:
   * Collapses one path (`/./`, `/../`) and returns `(collapsedPath, success)`.
   */
  int cfunc_FileCollapsePathL(LuaPlus::LuaState* state);

  /**
   * Address: 0x004575E0 (FUN_004575E0, func_FileCollapsePath_LuaFuncDef)
   *
   * What it does:
   * Returns the global Lua binder definition for `FileCollapsePath`.
   */
  [[nodiscard]] CScrLuaInitForm* func_FileCollapsePath_LuaFuncDef();

  /**
   * Address: 0x00BC45C0 (FUN_00BC45C0, register_DiskFindFiles_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_DiskFindFiles_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_DiskFindFiles_LuaFuncDef();

  /**
   * Address: 0x00BC45D0 (FUN_00BC45D0, register_DiskGetFileInfo_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_DiskGetFileInfo_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_DiskGetFileInfo_LuaFuncDef();

  /**
   * Address: 0x00BC45E0 (FUN_00BC45E0, register_DiskToLocal_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_DiskToLocal_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_DiskToLocal_LuaFuncDef();

  /**
   * Address: 0x00BC45F0 (FUN_00BC45F0, register_Basename_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_Basename_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_Basename_LuaFuncDef();

  /**
   * Address: 0x00BC4600 (FUN_00BC4600, register_Dirname_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_Dirname_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_Dirname_LuaFuncDef();

  /**
   * Address: 0x00BC4610 (FUN_00BC4610, register_FileCollapsePath_LuaFuncDef)
   *
   * What it does:
   * Startup thunk that forwards to `func_FileCollapsePath_LuaFuncDef`.
   */
  [[nodiscard]] CScrLuaInitForm* register_FileCollapsePath_LuaFuncDef();

  /**
    * Alias of FUN_00458D30 (non-canonical helper lane).
   *
   * What it does:
   * Resolves file metadata through the wait-handle/VFS runtime when available.
   * The recovered `realOnly` gate is preserved for callsite parity.
   */
  bool FILE_GetFileInfo(gpg::StrArg sourcePath, SDiskFileInfo* outInfo, bool realOnly);

  msvc8::string* FILE_ToMountedPath(msvc8::string* outPath, gpg::StrArg sourcePath);
} // namespace moho
