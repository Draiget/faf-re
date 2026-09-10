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
  [[nodiscard]]
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

  /**
   * Address: 0x004637D0 (FUN_004637D0, sub_4637D0)
   *
   * IDA signature:
   * int __usercall sub_4637D0@<eax>(const SDiskWatchEvent* event@<edi>, TDatListItem* listeners@<esi>);
   *
   * What it does:
   * Delivers one watch event to every listener. The whole list is spliced onto
   * a local head first and each node is relinked into the real list just
   * before its callback runs, so a listener may unlink itself or register
   * another during dispatch without the walk losing its place.
   */
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
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
  [[nodiscard]]
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

  // The map's own teardown is `~map()`, which MSVC emits for the member.
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

  if (mDirWatchMap.find(normalizedPath) != mDirWatchMap.end()) {
    gpg::Warnf("CDiskWatch::AddDirectory(): Attempting to add \"%s\" multiple times.", normalizedPath.c_str());
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  std::unique_ptr<CDiskDirWatch> dirWatch = std::make_unique<CDiskDirWatch>(this, normalizedPath.c_str());
  if (!dirWatch->HasValidHandle()) {
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  if (!mDirWatchMap.insert({normalizedPath, dirWatch.get()}).second) {
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
  const DiskWatchMap::iterator watched = mDirWatchMap.find(normalizedPath);
  if (watched == mDirWatchMap.end()) {
    gpg::Warnf("CDiskWatch::RemoveDirectory(): \"%s\" not being watched.", normalizedPath.c_str());
    gpg::core::func_UnlockShared(&mLock);
    return false;
  }

  delete watched->second;
  watched->second = nullptr;
  (void)mDirWatchMap.erase(watched);

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

  for (const auto& [directoryPath, dirWatch] : mDirWatchMap) {
    if (dirWatch != nullptr) {
      dirWatch->Update();
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
