#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Sync.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/containers/TDatList.h"

namespace moho
{
  class CDiskWatch;

  struct SDiskWatchEvent
  {
    msvc8::string mPath;          // +0x00
    std::int32_t mActionCode;     // +0x1C
    std::uint32_t mTimestampLow;  // +0x20
    std::uint32_t mTimestampHigh; // +0x24
  };

  struct SDiskWatchOverlappedRuntime
  {
    std::uintptr_t mInternal;      // +0x00
    std::uintptr_t mInternalHigh;  // +0x04
    std::uint32_t mOffset;         // +0x08
    std::uint32_t mOffsetHigh;     // +0x0C
    void* mEventHandle;            // +0x10
  };

  class CDiskDirWatch
  {
  public:
    /**
     * Address: 0x00461EF0 (FUN_00461EF0, ??0CDiskDirWatch@Moho@@QAE@PAVCDiskWatch@1@VStrArg@gpg@@@Z)
     *
     * What it does:
     * Binds one watch source to a lower-cased/chopped directory path and opens
     * the Win32 directory handle used by disk watch polling.
     */
    CDiskDirWatch(CDiskWatch* owner, gpg::StrArg directoryPath);

    /**
     * Address: 0x00462020 (FUN_00462020, ??1CDiskDirWatch@Moho@@QAE@XZ)
     *
     * What it does:
     * Closes the directory watch handle and releases watch-owned runtime
     * buffers.
     */
    ~CDiskDirWatch();

    /**
     * Address: 0x004620B0 (FUN_004620B0, ?Update@CDiskDirWatch@Moho@@QAEXXZ)
     *
     * What it does:
     * Polls one directory watch source and dispatches any resulting disk events.
     */
    void Update();

    [[nodiscard]]
    bool HasValidHandle() const;

  private:
    /**
     * Address: 0x00462700 (FUN_00462700, ?DoRead@CDiskDirWatch@Moho@@AAEXXZ)
     *
     * What it does:
     * Queues one asynchronous `ReadDirectoryChangesW` read for this directory.
     */
    void DoRead();

  public:
    CDiskWatch* mOwner;                // +0x00
    msvc8::vector<SDiskWatchEvent> mPendingEvents; // +0x04
    msvc8::string mDirectoryPath;      // +0x14
    void* mDirectoryHandle;            // +0x30
    msvc8::vector<std::uint8_t> mReadBuffer;       // +0x34
    SDiskWatchOverlappedRuntime mReadOverlapped;   // +0x44
  };

  /**
   * Address: 0x00411320 (?FILE_Wild@Moho@@YA_NVStrArg@gpg@@0_ND@Z)
   */
  bool FILE_Wild(gpg::StrArg path, gpg::StrArg pattern, bool caseSensitive = false, char pathSeparator = '\\');

  class CDiskWatchListener
  {
  public:
    /**
     * Address: 0x00461B10 (FUN_00461B10, ??0CDiskWatchListener@Moho@@QAE@VStrArg@gpg@@@Z)
     *
     * What it does:
     * Initializes listener storage and optionally auto-registers it using a wildcard pattern.
     */
    explicit CDiskWatchListener(gpg::StrArg patterns);

    /**
     * Address: 0x00461C30 (FUN_00461C30, ??1CDiskWatchListener@Moho@@QAE@XZ)
     *
     * What it does:
     * Unregisters from the active watch, then clears pattern/event vectors.
     */
    virtual ~CDiskWatchListener();

    /**
     * Address: 0x00461DC0 (FUN_00461DC0, ?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
     */
    virtual void OnEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461D00 (FUN_00461D00, ?FilterEvent@CDiskWatchListener@Moho@@UAE_NABUSDiskWatchEvent@2@@Z)
     */
    virtual bool FilterEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461DF0 (FUN_00461DF0, ?OnDiskWatchEvent@CDiskWatchListener@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
     */
    virtual void OnDiskWatchEvent(const SDiskWatchEvent& event);

    /**
     * Address: 0x00461E90 (FUN_00461E90, ?AnyChangesPending@CDiskWatchListener@Moho@@QAE_NXZ)
     */
    [[nodiscard]]
    bool AnyChangesPending();

    /**
     * Address: 0x00461E00 (FUN_00461E00,
     * ?CopyAndClearPendingChanges@CDiskWatchListener@Moho@@QAE?AV?$vector@USDiskWatchEvent@Moho@@V?$allocator@USDiskWatchEvent@Moho@@@std@@@std@@XZ)
     */
    void CopyAndClearPendingChanges(msvc8::vector<SDiskWatchEvent>& outEvents);

  public:
    TDatListItem<CDiskWatchListener, void> mLink; // +0x04
    CDiskWatch* mWatch;                           // +0x0C
    msvc8::vector<SDiskWatchEvent> mEvents;       // +0x10
    msvc8::vector<msvc8::string> mPatterns;       // +0x20
  };

  class CDiskWatch
  {
  public:
    struct DiskWatchMapNode
    {
      DiskWatchMapNode* mLeft;      // +0x00
      DiskWatchMapNode* mParent;    // +0x04
      DiskWatchMapNode* mRight;     // +0x08
      msvc8::string mDirectoryPath; // +0x0C
      CDiskDirWatch* mDirWatch;     // +0x28
      std::uint8_t mColor;          // +0x2C
      std::uint8_t mIsNil;          // +0x2D
      std::uint16_t mPadding2E;     // +0x2E
    };

    struct DiskWatchMap
    {
      void* mAllocProxy;          // +0x00
      DiskWatchMapNode* mHead;    // +0x04
      std::uint32_t mNodeCount;   // +0x08
    };

    /**
     * Address: 0x004627C0 (FUN_004627C0, ??0CDiskWatch@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes watch-list sentinel links and synchronization state.
     */
    CDiskWatch();

    /**
     * Address: 0x004628C0 (FUN_004628C0, ??1CDiskWatch@Moho@@QAE@XZ)
     *
     * What it does:
     * Unlinks listeners, releases all watched directories, and tears down the
     * lock/sentinel state (`0x00462870` is the local cleanup block).
     */
    ~CDiskWatch();

    /**
     * Address: 0x00462A30 (FUN_00462A30, ?AddListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
     */
    void AddListener(CDiskWatchListener* listener);

    /**
     * Address: 0x00462A80 (FUN_00462A80, ?RemoveListener@CDiskWatch@Moho@@QAEXPAVCDiskWatchListener@2@@Z)
     */
    void RemoveListener(CDiskWatchListener* listener);

    /**
     * Address: 0x00462AC0 (FUN_00462AC0, ?AddDirectory@CDiskWatch@Moho@@QAE_NVStrArg@gpg@@@Z)
     *
     * What it does:
     * Adds one lower-cased directory watch source to the watch map when not
     * already present.
     */
    bool AddDirectory(gpg::StrArg directoryPath);

    /**
     * Address: 0x00462DD0 (FUN_00462DD0, ?RemoveDirectoryW@CDiskWatch@Moho@@QAE_NVStrArg@gpg@@@Z)
     *
     * What it does:
     * Removes one lower-cased watch directory from the watch map and destroys
     * its owned `CDiskDirWatch` instance.
     */
    bool RemoveDirectoryW(gpg::StrArg directoryPath);

    /**
     * Address: 0x00462F80 (?EnablePrivileges@CDiskWatch@Moho@@ABE_NXZ)
     */
    [[nodiscard]]
    bool EnablePrivileges() const;

  private:
    /**
     * Address: 0x00463180 (FUN_00463180, ?EnablePrivilege@CDiskWatch@Moho@@ABE_NABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@_N@Z)
     *
     * What it does:
     * Opens the current process token and enables/disables one named privilege.
     */
    [[nodiscard]]
    bool EnablePrivilege(const msvc8::string& privilegeName, bool enable = true) const;

  public:
    /**
     * Address: 0x004629B0 (FUN_004629B0, ?WatchQuery@CDiskWatch@Moho@@QAEXXZ)
     *
     * What it does:
     * Locks the watch map and runs `CDiskDirWatch::Update()` for each registered
     * directory watcher entry.
     */
    void WatchQuery();

  public:
    TDatListItem<CDiskWatchListener, void> mListeners; // +0x00
    void* mUnknown08;                                  // +0x08
    gpg::core::SharedLock mLock;                       // +0x0C
    std::uint8_t mOpaque10[0x08];                      // +0x10
    DiskWatchMap mDirWatchMap;                         // +0x18
  };

  /**
   * Address: 0x004632B0 (?DISK_AddWatchDirectory@Moho@@YA_NVStrArg@gpg@@@Z)
   */
  bool DISK_AddWatchDirectory(gpg::StrArg directoryPath);

  /**
   * Address: 0x004632E0 (?DISK_RemoveWatchDirectory@Moho@@YA_NVStrArg@gpg@@@Z)
   */
  bool DISK_RemoveWatchDirectory(gpg::StrArg directoryPath);

  /**
   * Address: 0x00463310 (?DISK_AddWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
   */
  void DISK_AddWatchListener(CDiskWatchListener* listener);

  /**
   * Address: 0x00463340 (?DISK_RemoveWatchListener@Moho@@YAXPAVCDiskWatchListener@1@@Z)
   */
  void DISK_RemoveWatchListener(CDiskWatchListener* listener);

  /**
   * Address: 0x004633D0 (?DISK_ResetWatch@Moho@@YAXXZ)
   */
  void DISK_ResetWatch();

  /**
   * Address: 0x004633A0 (FUN_004633A0, ?DISK_UpdateWatcher@Moho@@YAXXZ)
   *
   * What it does:
   * Ensures the global disk-watch singleton exists, then pumps one watch-query
   * update pass.
   */
  void DISK_UpdateWatcher();

  static_assert(sizeof(SDiskWatchEvent) == 0x28, "SDiskWatchEvent size must be 0x28");
  static_assert(offsetof(SDiskWatchEvent, mActionCode) == 0x1C, "SDiskWatchEvent::mActionCode offset must be 0x1C");
  static_assert(sizeof(SDiskWatchOverlappedRuntime) == 0x14, "SDiskWatchOverlappedRuntime size must be 0x14");
  static_assert(sizeof(CDiskDirWatch) == 0x58, "CDiskDirWatch size must be 0x58");
  static_assert(offsetof(CDiskDirWatch, mPendingEvents) == 0x04, "CDiskDirWatch::mPendingEvents offset must be 0x04");
  static_assert(offsetof(CDiskDirWatch, mDirectoryPath) == 0x14, "CDiskDirWatch::mDirectoryPath offset must be 0x14");
  static_assert(offsetof(CDiskDirWatch, mDirectoryHandle) == 0x30, "CDiskDirWatch::mDirectoryHandle offset must be 0x30");
  static_assert(offsetof(CDiskDirWatch, mReadBuffer) == 0x34, "CDiskDirWatch::mReadBuffer offset must be 0x34");
  static_assert(offsetof(CDiskDirWatch, mReadOverlapped) == 0x44, "CDiskDirWatch::mReadOverlapped offset must be 0x44");
  static_assert(sizeof(CDiskWatchListener) == 0x30, "CDiskWatchListener size must be 0x30");
  static_assert(offsetof(CDiskWatchListener, mLink) == 0x04, "CDiskWatchListener::mLink offset must be 0x04");
  static_assert(offsetof(CDiskWatchListener, mWatch) == 0x0C, "CDiskWatchListener::mWatch offset must be 0x0C");
  static_assert(offsetof(CDiskWatchListener, mEvents) == 0x10, "CDiskWatchListener::mEvents offset must be 0x10");
  static_assert(offsetof(CDiskWatchListener, mPatterns) == 0x20, "CDiskWatchListener::mPatterns offset must be 0x20");
  static_assert(
    offsetof(CDiskWatch::DiskWatchMapNode, mDirectoryPath) == 0x0C,
    "CDiskWatch::DiskWatchMapNode::mDirectoryPath offset must be 0x0C"
  );
  static_assert(
    offsetof(CDiskWatch::DiskWatchMapNode, mDirWatch) == 0x28,
    "CDiskWatch::DiskWatchMapNode::mDirWatch offset must be 0x28"
  );
  static_assert(
    offsetof(CDiskWatch::DiskWatchMapNode, mIsNil) == 0x2D,
    "CDiskWatch::DiskWatchMapNode::mIsNil offset must be 0x2D"
  );
  static_assert(sizeof(CDiskWatch::DiskWatchMapNode) == 0x30, "CDiskWatch::DiskWatchMapNode size must be 0x30");
  static_assert(sizeof(CDiskWatch::DiskWatchMap) == 0x0C, "CDiskWatch::DiskWatchMap size must be 0x0C");
  static_assert(
    offsetof(CDiskWatch::DiskWatchMap, mHead) == 0x04,
    "CDiskWatch::DiskWatchMap::mHead offset must be 0x04"
  );
  static_assert(sizeof(CDiskWatch) == 0x24, "CDiskWatch size must be 0x24");
  static_assert(offsetof(CDiskWatch, mLock) == 0x0C, "CDiskWatch::mLock offset must be 0x0C");
  static_assert(
    offsetof(CDiskWatch, mDirWatchMap) == 0x18,
    "CDiskWatch::mDirWatchMap offset must be 0x18"
  );
} // namespace moho
