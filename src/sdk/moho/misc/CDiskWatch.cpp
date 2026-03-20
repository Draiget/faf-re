#include "CDiskWatch.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <utility>

using namespace moho;

namespace
{
  std::mutex gDiskWatchInitMutex;
  CDiskWatch* gDiskWatch = nullptr;

  char NormalizeWildcardChar(const char c, const bool caseSensitive)
  {
    if (caseSensitive) {
      return c;
    }
    return static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }

  bool MatchWildcardInternal(const char* text, const char* pattern, const bool caseSensitive)
  {
    const char* starPattern = nullptr;
    const char* starText = nullptr;

    while (*text) {
      if (*pattern == '*') {
        starPattern = pattern++;
        starText = text;
        continue;
      }

      const char pat = NormalizeWildcardChar(*pattern, caseSensitive);
      const char src = NormalizeWildcardChar(*text, caseSensitive);
      if (*pattern == '?' || pat == src) {
        ++pattern;
        ++text;
        continue;
      }

      if (!starPattern) {
        return false;
      }

      pattern = starPattern + 1;
      text = ++starText;
    }

    while (*pattern == '*') {
      ++pattern;
    }

    return *pattern == '\0';
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
bool moho::
  FILE_Wild(const gpg::StrArg path, const gpg::StrArg pattern, const bool caseSensitive, const char /*pathSeparator*/)
{
  if (!path || !pattern) {
    return false;
  }
  return MatchWildcardInternal(path, pattern, caseSensitive);
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
{
  mListeners.mPrev = &mListeners;
  mListeners.mNext = &mListeners;
  EnablePrivileges();
}

/**
 * Address: 0x00462870 (loc_462870, CDiskWatch cleanup helper)
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
 * Address: 0x00462F80 (?EnablePrivileges@CDiskWatch@Moho@@ABE_NXZ)
 */
bool CDiskWatch::EnablePrivileges() const
{
  // Recovery note:
  // privilege-token adjustment internals are not yet lifted; callers only
  // use this as a best-effort setup path.
  return true;
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
 * Address: 0x004633D0 (?DISK_ResetWatch@Moho@@YAXXZ)
 */
void moho::DISK_ResetWatch()
{
  std::lock_guard<std::mutex> lock(gDiskWatchInitMutex);
  delete gDiskWatch;
  gDiskWatch = nullptr;
}
