#include "WxRuntimeTypes.h"

#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <io.h>

#include "gpg/core/containers/String.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "moho/console/CConCommand.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/d3d/CD3DDevice.h"

class wxClassInfo;

class wxHashTableRuntime
{
public:
  wxHashTableRuntime(std::int32_t keyType, std::int32_t bucketHint);
  ~wxHashTableRuntime();

  /**
   * Address: 0x009D19B0 (FUN_009D19B0, wxHashTable::Put)
   *
   * What it does:
   * Inserts one class-info pointer into the runtime class-name lookup lane.
   */
  void Put(const wchar_t* key, wxClassInfo* classInfo);

  /**
   * Address: 0x009D1C90 (FUN_009D1C90, wxHashTable::Get)
   *
   * What it does:
   * Resolves one class-info pointer from the runtime class-name lookup lane.
   */
  [[nodiscard]] wxClassInfo* Get(const wchar_t* key) const;

private:
  std::int32_t mKeyType = 0;                                          // +0x00
  std::int32_t mBucketHint = 0;                                       // +0x04
  std::unordered_map<std::wstring, wxClassInfo*>* mEntries = nullptr; // +0x08
  std::uint8_t mReserved0C[0x18]{};                                   // +0x0C
};

static_assert(sizeof(wxHashTableRuntime) == 0x24, "wxHashTableRuntime size must be 0x24");

wxHashTableRuntime::wxHashTableRuntime(
  const std::int32_t keyType,
  const std::int32_t bucketHint
)
  : mKeyType(keyType)
  , mBucketHint(bucketHint)
  , mEntries(new std::unordered_map<std::wstring, wxClassInfo*>())
{
  if (mEntries != nullptr) {
    mEntries->reserve(static_cast<std::size_t>(bucketHint));
  }
}

wxHashTableRuntime::~wxHashTableRuntime()
{
  delete mEntries;
  mEntries = nullptr;
}

/**
 * Address: 0x009D19B0 (FUN_009D19B0, wxHashTable::Put)
 *
 * What it does:
 * Inserts one class-info pointer into the runtime class-name lookup lane.
 */
void wxHashTableRuntime::Put(
  const wchar_t* const key,
  wxClassInfo* const classInfo
)
{
  if (mEntries == nullptr || key == nullptr) {
    return;
  }

  (*mEntries)[key] = classInfo;
}

/**
 * Address: 0x009D1C90 (FUN_009D1C90, wxHashTable::Get)
 *
 * What it does:
 * Resolves one class-info pointer from the runtime class-name lookup lane.
 */
wxClassInfo* wxHashTableRuntime::Get(
  const wchar_t* const key
) const
{
  if (mEntries == nullptr || key == nullptr) {
    return nullptr;
  }

  const auto iter = mEntries->find(key);
  return iter != mEntries->end() ? iter->second : nullptr;
}

class wxClassInfo
{
public:
  /**
   * Address: 0x00977DA0 (FUN_00977DA0, wxClassInfo::InitializeClasses)
   *
   * What it does:
   * Builds one class-name lookup table from the linked class-info list, then
   * resolves primary/secondary base-class pointers from base-name lanes.
   */
  static void InitializeClasses()
  {
    sm_classTable = new wxHashTableRuntime(2, 1000);

    for (wxClassInfo* classInfo = sm_first; classInfo != nullptr; classInfo = classInfo->m_next) {
      if (classInfo->m_className != nullptr) {
        sm_classTable->Put(classInfo->m_className, classInfo);
      }
    }

    for (wxClassInfo* classInfo = sm_first; classInfo != nullptr; classInfo = classInfo->m_next) {
      classInfo->m_baseInfo1 =
        classInfo->m_baseClassName1 != nullptr ? sm_classTable->Get(classInfo->m_baseClassName1) : nullptr;
      classInfo->m_baseInfo2 =
        classInfo->m_baseClassName2 != nullptr ? sm_classTable->Get(classInfo->m_baseClassName2) : nullptr;
    }
  }

  static wxClassInfo* sm_first;
  static wxHashTableRuntime* sm_classTable;

  const wchar_t* m_className = nullptr;      // +0x00
  const wchar_t* m_baseClassName1 = nullptr; // +0x04
  const wchar_t* m_baseClassName2 = nullptr; // +0x08
  std::uint8_t mReserved0C[0x8]{};           // +0x0C
  wxClassInfo* m_baseInfo1 = nullptr;        // +0x14
  wxClassInfo* m_baseInfo2 = nullptr;        // +0x18
  wxClassInfo* m_next = nullptr;             // +0x1C
};

static_assert(offsetof(wxClassInfo, m_className) == 0x00, "wxClassInfo::m_className offset must be 0x00");
static_assert(offsetof(wxClassInfo, m_baseClassName1) == 0x04, "wxClassInfo::m_baseClassName1 offset must be 0x04");
static_assert(offsetof(wxClassInfo, m_baseClassName2) == 0x08, "wxClassInfo::m_baseClassName2 offset must be 0x08");
static_assert(offsetof(wxClassInfo, m_baseInfo1) == 0x14, "wxClassInfo::m_baseInfo1 offset must be 0x14");
static_assert(offsetof(wxClassInfo, m_baseInfo2) == 0x18, "wxClassInfo::m_baseInfo2 offset must be 0x18");
static_assert(offsetof(wxClassInfo, m_next) == 0x1C, "wxClassInfo::m_next offset must be 0x1C");
static_assert(sizeof(wxClassInfo) == 0x20, "wxClassInfo size must be 0x20");

wxClassInfo* wxClassInfo::sm_first = nullptr;
wxHashTableRuntime* wxClassInfo::sm_classTable = nullptr;

namespace
{
  constexpr std::uintptr_t kInlineHeadLinkSentinelMax = 0x10000u;
  constexpr long kWxWindowStyleVerticalScroll = static_cast<long>(0x80000000u);
  constexpr long kWxWindowStyleHorizontalScroll = static_cast<long>(0x40000000u);
  constexpr long kWxWindowStyleClipChildren = 0x00400000;
  constexpr long kWxWindowStyleRaisedBorder = 0x20000000;
  constexpr long kWxWindowStyleSunkenBorder = static_cast<long>(0x80000000u);
  constexpr long kWxWindowStyleDoubleBorder = 0x40000000;
  constexpr long kWxWindowStyleMaskForMsw = 0x1F200000;
  constexpr long kWxWindowStyleMaskAuto3DBase = 0x17200000;
  constexpr long kWxWindowStyleNo3D = 0x00800000;
  constexpr long kWxWindowStyleAuto3D = 0x08000000;
  constexpr long kWxWindowStyleStaticEdge = 0x02000000;
  constexpr long kWxWindowStyleSimpleBorder = 0x01000000;
  constexpr long kWxWindowStyleDoubleBorderLegacy = 0x04000000;
  constexpr long kWxWindowStyleSimpleBorderAlt = 0x10000000;
  constexpr long kWxWindowStyleNoParentBg = 0x00080000;
  constexpr long kWxWindowStyleTabTraversal = 0x00100000;
  constexpr unsigned long kMswStyleBase = 0x50000000u;
  constexpr unsigned long kMswStyleClipChildren = 0x52000000u;
  constexpr unsigned long kMswStyleRaisedBorder = 0x04000000u;
  constexpr unsigned long kMswStyleSunkenBorder = 0x00200000u;
  constexpr unsigned long kMswStyleDoubleBorder = 0x00100000u;
  constexpr unsigned long kMswStyleNo3DBit = 0x00800000u;
  constexpr unsigned long kMswExStyleTabTraversal = 0x20u;
  constexpr unsigned long kMswExStyleClientEdge = 0x200u;
  constexpr unsigned long kMswExStyleDlgModalFrame = 0x1u;
  constexpr unsigned long kMswExStyleNoParentNotify = 0x00010000u;
  constexpr long kWxTextCtrlStyleMultiline = 0x20;
  constexpr long kWxTextCtrlStylePassword = 0x800;
  constexpr long kWxTextCtrlStyleReadOnly = 0x10;
  constexpr long kWxTextCtrlStyleProcessEnter = 0x400;
  constexpr long kWxTextCtrlStyleCenter = 0x100;
  constexpr long kWxTextCtrlStyleRight = 0x200;
  constexpr unsigned int kWin32CommandMessageId = 0x111u;
  constexpr std::uint32_t kDoMessageDeferredQueueInitialized = 0x1u;

  void* gCLogAdditionEventClassInfoTable[1] = {nullptr};
  void* gWxWindowBaseClassInfoTable[1] = {nullptr};
  void* gWxWindowClassInfoTable[1] = {nullptr};
  void* gWxImageHandlerClassInfoTable[1] = {nullptr};
  void* gWxPngHandlerClassInfoTable[1] = {nullptr};

  MSG gCurrentMessage{};
  std::uint32_t gDoMessageStateFlags = 0u;
  bool gIsDispatchingDeferredMessages = false;
  bool gSuppressDeferredCommandMessages = false;
  DWORD gs_idMainThread = ::GetCurrentThreadId();
  CRITICAL_SECTION gCritSectGui{};
  CRITICAL_SECTION gCritSectWaitingForGui{};
  _RTL_CRITICAL_SECTION* gs_critsectGui = nullptr;
  _RTL_CRITICAL_SECTION* gs_critsectWaitingForGui = nullptr;
  std::once_flag gGuiMutexInitOnce{};
  std::int32_t gs_nWaitingForGui = 0;
  std::uint8_t gs_bGuiOwnedByMainThread = 1;
  std::vector<MSG*>* gDeferredThreadMessages = nullptr;
  int gWxGetOsVersionCache = -1;
  int gWxGetOsVersionMajor = -1;
  int gWxGetOsVersionMinor = -1;
  HCURSOR gs_wxBusyCursor = nullptr;
  HCURSOR gs_wxBusyCursorOld = nullptr;
  int gs_wxBusyCursorCount = 0;

  struct WxWindowHandleHashEntryRuntime
  {
    std::uint8_t reserved00[0x8];
    wxWindowMswRuntime* window = nullptr;
  };
  static_assert(
    offsetof(WxWindowHandleHashEntryRuntime, window) == 0x8,
    "WxWindowHandleHashEntryRuntime::window offset must be 0x8"
  );

  class WxWindowHandleHashRuntime
  {
  public:
    void* Get(int key, void* frameHandle);
  };

  WxWindowHandleHashRuntime* wxWinHandleHash = nullptr;

  void* WxWindowHandleHashRuntime::Get(
    const int,
    void*
  )
  {
    return nullptr;
  }

  void DestroyDeferredThreadMessages() noexcept
  {
    if (gDeferredThreadMessages == nullptr) {
      return;
    }

    for (MSG* const queuedMessage : *gDeferredThreadMessages) {
      delete queuedMessage;
    }
    gDeferredThreadMessages->clear();
    delete gDeferredThreadMessages;
    gDeferredThreadMessages = nullptr;
  }

  void EnsureDeferredThreadMessageQueueInitialized()
  {
    if (gDeferredThreadMessages == nullptr) {
      gDeferredThreadMessages = new std::vector<MSG*>();
    }

    if ((gDoMessageStateFlags & kDoMessageDeferredQueueInitialized) != 0u) {
      return;
    }

    gDoMessageStateFlags |= kDoMessageDeferredQueueInitialized;
    std::atexit(&DestroyDeferredThreadMessages);
  }

  void EnsureGuiMutexRuntimeInitialized() noexcept
  {
    std::call_once(gGuiMutexInitOnce, []() {
      ::InitializeCriticalSection(&gCritSectGui);
      ::InitializeCriticalSection(&gCritSectWaitingForGui);
      gs_critsectGui = reinterpret_cast<_RTL_CRITICAL_SECTION*>(&gCritSectGui);
      gs_critsectWaitingForGui = reinterpret_cast<_RTL_CRITICAL_SECTION*>(&gCritSectWaitingForGui);
    });
  }

  [[nodiscard]] _RTL_CRITICAL_SECTION* GuiCriticalSection() noexcept
  {
    EnsureGuiMutexRuntimeInitialized();
    return gs_critsectGui;
  }

  [[nodiscard]] _RTL_CRITICAL_SECTION* WaitingForGuiCriticalSection() noexcept
  {
    EnsureGuiMutexRuntimeInitialized();
    return gs_critsectWaitingForGui;
  }

  [[nodiscard]] bool IsGuiOwnedByMainThread() noexcept
  {
    return wxGuiOwnedByMainThread();
  }

  [[nodiscard]] bool ShouldSuppressDeferredCommandMessages() noexcept
  {
    return gSuppressDeferredCommandMessages;
  }

  void QueueDeferredThreadMessage(
    const MSG& message,
    const unsigned int repeatCount
  )
  {
    if (repeatCount == 0u) {
      return;
    }

    EnsureDeferredThreadMessageQueueInitialized();
    gDeferredThreadMessages->reserve(gDeferredThreadMessages->size() + repeatCount);

    for (unsigned int index = 0; index < repeatCount; ++index) {
      gDeferredThreadMessages->push_back(new MSG(message));
    }
  }

  void DispatchDeferredThreadMessages(
    wxApp& app
  )
  {
    if (gIsDispatchingDeferredMessages) {
      return;
    }

    gIsDispatchingDeferredMessages = true;
    if (gDeferredThreadMessages == nullptr) {
      return;
    }

    const std::size_t deferredCount = gDeferredThreadMessages->size();
    for (std::size_t index = 0; index < deferredCount; ++index) {
      MSG* const queuedMessage = (*gDeferredThreadMessages)[index];
      if (queuedMessage != nullptr) {
        app.ProcessMessage(reinterpret_cast<void**>(queuedMessage));
      }
    }
    DestroyDeferredThreadMessages();
  }

  struct WxObjectRuntimeView
  {
    void* vtable = nullptr;
    void* refData = nullptr;
  };

  struct WxCursorRefDataRuntimeView
  {
    std::uint8_t reserved00_13[0x14];
    void* nativeCursorHandle = nullptr; // +0x14
  };
  static_assert(
    offsetof(WxCursorRefDataRuntimeView, nativeCursorHandle) == 0x14,
    "WxCursorRefDataRuntimeView::nativeCursorHandle offset must be 0x14"
  );

  /**
   * Runtime view for wxImage::m_refData allocated by `FUN_009703B0`.
   *
   * The binary lane seeds width/height/data at +0x08/+0x0C/+0x10, stores
   * six flag bytes at +0x14..+0x19, and constructs opaque palette/string
   * helper lanes from +0x1C onward.
   */
  class WxImageRefDataRuntime final
  {
  public:
    WxImageRefDataRuntime() = default;

    virtual ~WxImageRefDataRuntime()
    {
      std::free(mPixelBytes);
      mPixelBytes = nullptr;
    }

    std::int32_t mRefCount = 1;
    std::int32_t mWidth = 0;
    std::int32_t mHeight = 0;
    std::uint8_t* mPixelBytes = nullptr;
    std::uint8_t mMaskAndFlags[0x8]{};
    std::uint8_t mPaletteRuntimeLane[0xC]{};
    std::uint8_t mArrayStringLane0[0x10]{};
    std::uint8_t mArrayStringLane1[0x10]{};
  };

  static_assert(
    offsetof(WxImageRefDataRuntime, mRefCount) == 0x4,
    "WxImageRefDataRuntime::mRefCount offset must be 0x4"
  );
  static_assert(offsetof(WxImageRefDataRuntime, mWidth) == 0x8, "WxImageRefDataRuntime::mWidth offset must be 0x8");
  static_assert(offsetof(WxImageRefDataRuntime, mHeight) == 0xC, "WxImageRefDataRuntime::mHeight offset must be 0xC");
  static_assert(
    offsetof(WxImageRefDataRuntime, mPixelBytes) == 0x10,
    "WxImageRefDataRuntime::mPixelBytes offset must be 0x10"
  );
  static_assert(
    offsetof(WxImageRefDataRuntime, mMaskAndFlags) == 0x14,
    "WxImageRefDataRuntime::mMaskAndFlags offset must be 0x14"
  );
  static_assert(sizeof(WxImageRefDataRuntime) == 0x48, "WxImageRefDataRuntime size must be 0x48");

  /**
   * Address: 0x0042B9D0 (FUN_0042B9D0)
   *
   * What it does:
   * Shared wx-object unref tail used by destructor paths that only clear
   * ref-data ownership.
   */
  void RunWxObjectUnrefTail(
    WxObjectRuntimeView* const object
  ) noexcept
  {
    if (object == nullptr) {
      return;
    }
    object->refData = nullptr;
  }

  void ReleaseWxStringSharedPayload(
    wxStringRuntime& value
  ) noexcept
  {
    std::int32_t* const sharedPrefixWords = reinterpret_cast<std::int32_t*>(value.m_pchData) - 3;
    const std::int32_t sharedRefCount = sharedPrefixWords[0];
    if (sharedRefCount != -1) {
      sharedPrefixWords[0] = sharedRefCount - 1;
      if (sharedRefCount == 1) {
        ::operator delete(sharedPrefixWords);
      }
    }
  }

  struct WxOwnedStringHeader
  {
    std::int32_t refCount = 1;
    std::int32_t length = 0;
    std::int32_t capacity = 0;
  };

  std::mutex gOwnedWxStringLock{};
  std::unordered_set<void*> gOwnedWxStringHeaders{};

  [[nodiscard]] wxStringRuntime AllocateOwnedWxString(
    const std::wstring& value
  )
  {
    const std::size_t payloadBytes = sizeof(WxOwnedStringHeader) + (value.size() + 1) * sizeof(wchar_t);
    auto* const raw = static_cast<std::uint8_t*>(::operator new(payloadBytes));
    auto* const header = reinterpret_cast<WxOwnedStringHeader*>(raw);
    header->refCount = 1;
    header->length = static_cast<std::int32_t>(value.size());
    header->capacity = static_cast<std::int32_t>(value.size());

    auto* const text = reinterpret_cast<wchar_t*>(raw + sizeof(WxOwnedStringHeader));
    std::wmemcpy(text, value.c_str(), value.size());
    text[value.size()] = L'\0';

    {
      const std::lock_guard<std::mutex> lock(gOwnedWxStringLock);
      gOwnedWxStringHeaders.insert(header);
    }

    wxStringRuntime runtime{};
    runtime.m_pchData = text;
    return runtime;
  }

  [[nodiscard]] bool IsOwnedWxString(
    const wxStringRuntime& value
  ) noexcept
  {
    if (value.m_pchData == nullptr) {
      return false;
    }

    void* const header = reinterpret_cast<void*>(reinterpret_cast<std::int32_t*>(value.m_pchData) - 3);
    const std::lock_guard<std::mutex> lock(gOwnedWxStringLock);
    return gOwnedWxStringHeaders.find(header) != gOwnedWxStringHeaders.end();
  }

  void ReleaseOwnedWxString(
    wxStringRuntime& value
  ) noexcept
  {
    if (!IsOwnedWxString(value)) {
      value.m_pchData = nullptr;
      return;
    }

    auto* const header = reinterpret_cast<WxOwnedStringHeader*>(reinterpret_cast<std::int32_t*>(value.m_pchData) - 3);
    if (header->refCount > 1) {
      --header->refCount;
      value.m_pchData = nullptr;
      return;
    }

    {
      const std::lock_guard<std::mutex> lock(gOwnedWxStringLock);
      gOwnedWxStringHeaders.erase(header);
    }
    ::operator delete(header);
    value.m_pchData = nullptr;
  }

  void AssignOwnedWxString(
    wxStringRuntime* const outValue,
    const std::wstring& value
  )
  {
    if (outValue == nullptr) {
      return;
    }

    ReleaseOwnedWxString(*outValue);
    *outValue = AllocateOwnedWxString(value);
  }

  void PrependOwnedWxString(
    wxStringRuntime* const target,
    const wxStringRuntime& prefix
  )
  {
    if (target == nullptr) {
      return;
    }

    std::wstring combined(prefix.c_str());
    combined += target->c_str();
    AssignOwnedWxString(target, combined);
  }

  /**
   * Address: 0x00960970 (FUN_00960970, wxString copy-before-write helper)
   *
   * What it does:
   * Ensures one wx string lane has unique writable ownership; when the shared
   * refcount is greater than 1, it decrements the old header refcount and
   * allocates/copies a private payload for the caller.
   */
  [[nodiscard]] bool EnsureUniqueOwnedWxStringBuffer(
    wxStringRuntime* const value
  )
  {
    if (value == nullptr || value->m_pchData == nullptr || !IsOwnedWxString(*value)) {
      return false;
    }

    auto* const header = reinterpret_cast<WxOwnedStringHeader*>(reinterpret_cast<std::int32_t*>(value->m_pchData) - 3);
    const std::int32_t refCount = header->refCount;
    if (refCount > 1) {
      header->refCount = refCount - 1;

      const std::size_t currentLength = static_cast<std::size_t>(header->length < 0 ? 0 : header->length);
      std::wstring copiedText(value->m_pchData, currentLength);
      *value = AllocateOwnedWxString(copiedText);
    }

    return true;
  }

  /**
   * Address: 0x00980B70 (FUN_00980B70)
   *
   * What it does:
   * Tears down one `wxListItemAttr` payload by releasing the embedded font and
   * colour wxObject ref-data lanes in reverse construction order.
   */
  void DestroyWxListItemAttrRuntime(
    wxListItemAttrRuntime* const attr
  ) noexcept
  {
    if (attr == nullptr) {
      return;
    }

    RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(&attr->mFont));
    RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(&attr->mBackgroundColour));
    RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(&attr->mTextColour));
  }

  void ReleaseD3DDeviceRef(
    void* const device
  ) noexcept
  {
    if (device == nullptr) {
      return;
    }

    void** const vtable = *reinterpret_cast<void***>(device);
    if (vtable == nullptr || vtable[1] == nullptr) {
      return;
    }

    using ReleaseFn = void(__thiscall*)(void*, unsigned int);
    auto const release = reinterpret_cast<ReleaseFn>(vtable[1]);
    release(device, 1u);
  }

  [[nodiscard]] bool IsInlineHeadLinkSentinel(
    moho::ManagedWindowSlot** const ownerHeadLink
  ) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ownerHeadLink) < kInlineHeadLinkSentinelMax;
  }

  [[nodiscard]] moho::ManagedWindowSlot* TranslateSlotPointerForReallocation(
    moho::ManagedWindowSlot* const pointer,
    const moho::ManagedWindowSlot* const oldStorage,
    const std::size_t oldCount,
    moho::ManagedWindowSlot* const newStorage
  ) noexcept
  {
    if (pointer == nullptr || oldStorage == nullptr || oldCount == 0 || newStorage == nullptr) {
      return pointer;
    }

    const std::uintptr_t oldBegin = reinterpret_cast<std::uintptr_t>(oldStorage);
    const std::uintptr_t oldEnd = oldBegin + oldCount * sizeof(moho::ManagedWindowSlot);
    const std::uintptr_t pointerValue = reinterpret_cast<std::uintptr_t>(pointer);
    if (pointerValue < oldBegin || pointerValue >= oldEnd) {
      return pointer;
    }

    const std::size_t index = (pointerValue - oldBegin) / sizeof(moho::ManagedWindowSlot);
    return &newStorage[index];
  }

  void RebaseManagedSlotPointersAfterReallocation(
    msvc8::vector<moho::ManagedWindowSlot>& slots,
    const moho::ManagedWindowSlot* const oldStorage,
    const std::size_t oldCount
  ) noexcept
  {
    if (oldStorage == nullptr || oldCount == 0) {
      return;
    }

    moho::ManagedWindowSlot* const newStorage = slots.data();
    if (newStorage == nullptr || newStorage == oldStorage) {
      return;
    }

    const std::size_t newCount = slots.size();
    for (std::size_t index = 0; index < newCount; ++index) {
      moho::ManagedWindowSlot& slot = newStorage[index];
      slot.nextInOwnerChain =
        TranslateSlotPointerForReallocation(slot.nextInOwnerChain, oldStorage, oldCount, newStorage);
    }

    for (std::size_t index = 0; index < newCount; ++index) {
      moho::ManagedWindowSlot& slot = newStorage[index];
      if (slot.ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(slot.ownerHeadLink)) {
        continue;
      }

      moho::ManagedWindowSlot* const translatedHead =
        TranslateSlotPointerForReallocation(*slot.ownerHeadLink, oldStorage, oldCount, newStorage);
      if (*slot.ownerHeadLink != translatedHead) {
        *slot.ownerHeadLink = translatedHead;
      }
    }
  }

  void DetachSlotWithoutClearing(
    moho::ManagedWindowSlot& slot
  ) noexcept
  {
    if (slot.ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(slot.ownerHeadLink)) {
      return;
    }

    moho::ManagedWindowSlot** link = slot.ownerHeadLink;
    while (*link != nullptr && *link != &slot) {
      link = &(*link)->nextInOwnerChain;
    }

    if (*link == &slot) {
      *link = slot.nextInOwnerChain;
    }
  }

  void RelinkSlotToOwner(
    moho::ManagedWindowSlot& slot,
    moho::ManagedWindowSlot** const ownerHeadLink
  ) noexcept
  {
    if (slot.ownerHeadLink == ownerHeadLink) {
      return;
    }

    DetachSlotWithoutClearing(slot);
    slot.ownerHeadLink = ownerHeadLink;
    if (ownerHeadLink == nullptr) {
      slot.nextInOwnerChain = nullptr;
      return;
    }

    slot.nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = &slot;
  }

  template <typename TOwnerRuntime>
  [[nodiscard]] bool IsReusableManagedSlot(
    const moho::ManagedWindowSlot& slot
  )
  {
    return slot.ownerHeadLink == nullptr || slot.ownerHeadLink == TOwnerRuntime::NullManagedSlotHeadLinkSentinel();
  }

  template <typename TOwnerRuntime>
  [[nodiscard]] bool TryReuseManagedSlot(
    msvc8::vector<moho::ManagedWindowSlot>& slots,
    moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    moho::ManagedWindowSlot* const slotStorage = slots.data();
    if (slotStorage == nullptr) {
      return false;
    }

    const std::size_t slotCount = slots.size();
    for (std::size_t index = 0; index < slotCount; ++index) {
      moho::ManagedWindowSlot& slot = slotStorage[index];
      if (!IsReusableManagedSlot<TOwnerRuntime>(slot)) {
        continue;
      }

      RelinkSlotToOwner(slot, ownerHeadLink);
      return true;
    }

    return false;
  }

  template <typename TOwnerRuntime>
  void AppendManagedSlot(
    msvc8::vector<moho::ManagedWindowSlot>& slots,
    moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    if (ownerHeadLink == nullptr) {
      return;
    }

    moho::ManagedWindowSlot appendedSlot{};
    appendedSlot.ownerHeadLink = ownerHeadLink;
    appendedSlot.nextInOwnerChain = *ownerHeadLink;

    moho::ManagedWindowSlot* const oldStorage = slots.data();
    const std::size_t oldCount = slots.size();
    slots.push_back(appendedSlot);

    RebaseManagedSlotPointersAfterReallocation(slots, oldStorage, oldCount);

    moho::ManagedWindowSlot* const slotStorage = slots.data();
    if (slotStorage == nullptr || slots.empty()) {
      return;
    }

    moho::ManagedWindowSlot& insertedSlot = slotStorage[slots.size() - 1];
    insertedSlot.ownerHeadLink = ownerHeadLink;
    *ownerHeadLink = &insertedSlot;
  }

  template <typename TOwnerRuntime>
  void RegisterManagedOwnerSlotImpl(
    msvc8::vector<moho::ManagedWindowSlot>& slots,
    moho::ManagedWindowSlot** const ownerHeadLink
  )
  {
    if (ownerHeadLink == nullptr) {
      return;
    }

    if (TryReuseManagedSlot<TOwnerRuntime>(slots, ownerHeadLink)) {
      return;
    }

    AppendManagedSlot<TOwnerRuntime>(slots, ownerHeadLink);
  }

  void ReleaseManagedOwnerSlotChain(
    moho::ManagedWindowSlot*& ownerHead
  ) noexcept
  {
    while (ownerHead != nullptr) {
      moho::ManagedWindowSlot* const slot = ownerHead;
      ownerHead = slot->nextInOwnerChain;
      slot->Clear();
    }
  }

  template <typename TOwnerRuntime>
  void DestroyManagedRuntimeCollection(
    msvc8::vector<moho::ManagedWindowSlot>& slots
  )
  {
    for (std::size_t index = 0;; ++index) {
      moho::ManagedWindowSlot* slotStorage = slots.data();
      const std::size_t slotCount = slots.size();
      if (slotStorage == nullptr || index >= slotCount) {
        break;
      }

      moho::ManagedWindowSlot& slot = slotStorage[index];
      if (slot.ownerHeadLink == nullptr || slot.ownerHeadLink == TOwnerRuntime::NullManagedSlotHeadLinkSentinel()) {
        continue;
      }

      TOwnerRuntime* const owner = TOwnerRuntime::FromManagedSlotHeadLink(slot.ownerHeadLink);
      if (owner != nullptr) {
        (void)owner->Destroy();
      }

      slotStorage = slots.data();
      if (slotStorage == nullptr || index >= slots.size()) {
        continue;
      }
      slotStorage[index].UnlinkFromOwner();
    }
  }

  struct SupComFrameState
  {
    std::int32_t clientWidth = 0;
    std::int32_t clientHeight = 0;
    std::int32_t minWidth = 0;
    std::int32_t minHeight = 0;
    std::int32_t windowX = -1;
    std::int32_t windowY = -1;
    std::int32_t windowStyle = 0;
    bool visible = false;
    bool maximized = false;
    bool focused = false;
    bool iconized = false;
    bool iconResourceAssigned = false;
    std::uintptr_t pseudoWindowHandle = 0;
    std::wstring title;
    std::wstring name;
    std::wstring iconResourceName;
  };

  constexpr std::uintptr_t kFirstSupComFramePseudoHandle = 0x1000u;
  constexpr std::uintptr_t kSupComFramePseudoHandleStride = 0x10u;
  constexpr wchar_t kSupComFrameWindowName[] = L"frame";
  constexpr wchar_t kSupComFrameIconResourceName[] = L"ID";

  std::uintptr_t gNextSupComFramePseudoHandle = kFirstSupComFramePseudoHandle;
  std::unordered_map<const WSupComFrame*, SupComFrameState> gSupComFrameStateByFrame{};
  struct WxTopLevelWindowRuntimeState
  {
    std::int32_t fsOldX = 0;
    std::int32_t fsOldY = 0;
    std::int32_t fsOldWidth = 0;
    std::int32_t fsOldHeight = 0;
    std::uint8_t flag34 = 0;
  };

  struct WxDialogRuntimeState
  {
    void* parentWindow = nullptr;
    std::int32_t windowId = -1;
    wxPoint position{};
    wxSize size{};
    long style = 0;
    std::wstring title{};
    std::wstring name{};
  };

  std::unordered_map<const wxTopLevelWindowRuntime*, WxTopLevelWindowRuntimeState>
    gWxTopLevelWindowRuntimeStateByWindow{};
  std::unordered_map<const wxDialogRuntime*, WxDialogRuntimeState> gWxDialogRuntimeStateByDialog{};

  struct WxTreeListNodeRuntimeState
  {
    WxTreeListNodeRuntimeState* parent = nullptr;
    std::vector<WxTreeListNodeRuntimeState*> children{};
    wxTreeItemDataRuntime* itemData = nullptr;
    bool hasChildrenFlag = false;
    bool isExpanded = false;
    std::vector<msvc8::string> columnText{};
  };

  struct WxTreeListRuntimeState
  {
    wxWindowBase* parentWindow = nullptr;
    std::int32_t windowId = -1;
    wxPoint position{};
    wxSize size{};
    long style = 0;
    std::wstring name{};
    std::vector<wxTreeListColumnInfoRuntime> columns{};
    std::vector<std::unique_ptr<WxTreeListNodeRuntimeState>> nodeStorage{};
    WxTreeListNodeRuntimeState* rootNode = nullptr;
  };

  std::unordered_map<const wxTreeListCtrlRuntime*, WxTreeListRuntimeState> gWxTreeListRuntimeStateByControl{};

  struct WxWindowBaseRuntimeState
  {
    std::int32_t minWidth = -1;
    std::int32_t minHeight = -1;
    std::int32_t maxWidth = -1;
    std::int32_t maxHeight = -1;
    long windowStyle = 0;
    long extraStyle = 0;
    unsigned long nativeHandle = 0;
    std::int32_t windowId = -1;
    wxWindowBase* parentWindow = nullptr;
    wxWindowBase* eventHandler = nullptr;
    bool themeEnabled = false;
    std::uint8_t bitfields = 0;
    std::wstring windowName{};
    wxColourRuntime backgroundColour{};
    void* dropTarget = nullptr;
  };

  struct WxTextCtrlRuntimeState
  {
    std::int32_t richEditMajorVersion = 0;
  };

  struct WxWindowCaptureHistoryNode
  {
    wxWindowBase* window = nullptr;
    WxWindowCaptureHistoryNode* next = nullptr;
  };

  std::unordered_map<const wxWindowBase*, WxWindowBaseRuntimeState> gWxWindowBaseStateByWindow{};
  std::unordered_map<const wxTextCtrlRuntime*, WxTextCtrlRuntimeState> gWxTextCtrlStateByControl{};
  wxWindowBase* gCapturedWindow = nullptr;
  WxWindowCaptureHistoryNode* gWindowCaptureHistoryHead = nullptr;
  bool gSplashPngHandlerInitialized = false;
  std::unordered_map<COLORREF, HBRUSH> gCtlColorBrushByColor{};
  bool gCtlColorBrushCacheCleanupRegistered = false;

  void CleanupCtlColorBrushCache() noexcept
  {
    for (const auto& [_, brush] : gCtlColorBrushByColor) {
      if (brush != nullptr) {
        ::DeleteObject(brush);
      }
    }
    gCtlColorBrushByColor.clear();
  }

  [[nodiscard]] HBRUSH GetOrCreateCtlColorBrush(
    const COLORREF color
  ) noexcept
  {
    const auto existing = gCtlColorBrushByColor.find(color);
    if (existing != gCtlColorBrushByColor.end() && existing->second != nullptr) {
      return existing->second;
    }

    HBRUSH brush = ::CreateSolidBrush(color);
    if (brush == nullptr) {
      brush = static_cast<HBRUSH>(::GetStockObject(WHITE_BRUSH));
      return brush;
    }

    if (!gCtlColorBrushCacheCleanupRegistered) {
      gCtlColorBrushCacheCleanupRegistered = true;
      std::atexit(&CleanupCtlColorBrushCache);
    }

    gCtlColorBrushByColor[color] = brush;
    return brush;
  }

  struct WxDropFilesArrayStorage
  {
    std::uint32_t fileCount = 0;
  };

  int wxNewEventType()
  {
    static std::int32_t nextRuntimeEventType = 10000;
    return ++nextRuntimeEventType;
  }
  std::int32_t gWxEvtIdleRuntimeType = 0;
  std::int32_t gWxEvtDropFilesRuntimeType = 0;
  std::int32_t gWxEvtMouseCaptureChangedRuntimeType = 0;

  [[nodiscard]] std::int32_t EnsureWxEvtIdleRuntimeType()
  {
    if (gWxEvtIdleRuntimeType == 0) {
      gWxEvtIdleRuntimeType = wxNewEventType();
    }
    return gWxEvtIdleRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtDropFilesRuntimeType()
  {
    if (gWxEvtDropFilesRuntimeType == 0) {
      gWxEvtDropFilesRuntimeType = wxNewEventType();
    }
    return gWxEvtDropFilesRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtMouseCaptureChangedRuntimeType()
  {
    if (gWxEvtMouseCaptureChangedRuntimeType == 0) {
      gWxEvtMouseCaptureChangedRuntimeType = wxNewEventType();
    }
    return gWxEvtMouseCaptureChangedRuntimeType;
  }

  class WxIdleEventRuntime final : public wxEventRuntime
  {
  public:
    WxIdleEventRuntime()
      : wxEventRuntime(0, EnsureWxEvtIdleRuntimeType())
      , mRequestMore(false)
      , mPadding21To23{0, 0, 0}
    {}

    WxIdleEventRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxIdleEventRuntime();
      if (clone == nullptr) {
        return nullptr;
      }

      clone->mRefData = mRefData;
      clone->mEventObject = mEventObject;
      clone->mEventType = mEventType;
      clone->mEventTimestamp = mEventTimestamp;
      clone->mEventId = mEventId;
      clone->mCallbackUserData = mCallbackUserData;
      clone->mSkipped = mSkipped;
      clone->mIsCommandEvent = mIsCommandEvent;
      clone->mReserved1E = mReserved1E;
      clone->mReserved1F = mReserved1F;
      clone->mRequestMore = mRequestMore;
      return clone;
    }

    bool mRequestMore;
    std::uint8_t mPadding21To23[0x03];
  };

  static_assert(
    offsetof(WxIdleEventRuntime, mRequestMore) == 0x20,
    "WxIdleEventRuntime::mRequestMore offset must be 0x20"
  );
  static_assert(sizeof(WxIdleEventRuntime) == 0x24, "WxIdleEventRuntime size must be 0x24");

  class WxDropFilesEventRuntime final : public wxEventRuntime
  {
  public:
    WxDropFilesEventRuntime()
      : wxEventRuntime(0, EnsureWxEvtDropFilesRuntimeType())
    {}

    ~WxDropFilesEventRuntime()
    {
      ReleaseFileArray();
      RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
    }

    WxDropFilesEventRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxDropFilesEventRuntime();
      if (clone == nullptr) {
        return nullptr;
      }

      clone->mEventObject = mEventObject;
      clone->mEventType = mEventType;
      clone->mEventTimestamp = mEventTimestamp;
      clone->mEventId = mEventId;
      clone->mCallbackUserData = mCallbackUserData;
      clone->mSkipped = mSkipped;
      clone->mIsCommandEvent = mIsCommandEvent;
      clone->mReserved1E = mReserved1E;
      clone->mReserved1F = mReserved1F;
      clone->mDropPointX = mDropPointX;
      clone->mDropPointY = mDropPointY;
      clone->AssignFiles(mFiles, mFileCount);
      return clone;
    }

    void PopulateFromDropHandle(
      const HDROP dropHandle
    )
    {
      const std::uint32_t fileCount =
        static_cast<std::uint32_t>(::DragQueryFileW(dropHandle, 0xFFFFFFFFu, nullptr, 0u));
      AllocateFileArray(fileCount);
      for (std::uint32_t fileIndex = 0; fileIndex < mFileCount; ++fileIndex) {
        const UINT fileNameLength = ::DragQueryFileW(dropHandle, fileIndex, nullptr, 0u);
        auto* const fileName = new (std::nothrow) wchar_t[fileNameLength + 1u];
        if (fileName == nullptr) {
          continue;
        }

        const UINT copiedLength = ::DragQueryFileW(dropHandle, fileIndex, fileName, fileNameLength + 1u);
        fileName[copiedLength] = L'\0';
        mFiles[fileIndex] = wxStringRuntime::Borrow(fileName);
      }
    }

    std::uint32_t mFileCount = 0;
    std::int32_t mDropPointX = 0;
    std::int32_t mDropPointY = 0;
    wxStringRuntime* mFiles = nullptr;

  private:
    void AllocateFileArray(
      const std::uint32_t fileCount
    )
    {
      ReleaseFileArray();
      if (fileCount == 0u) {
        return;
      }

      const std::size_t storageBytes =
        sizeof(WxDropFilesArrayStorage) + sizeof(wxStringRuntime) * static_cast<std::size_t>(fileCount);
      auto* const storage = static_cast<WxDropFilesArrayStorage*>(::operator new(storageBytes, std::nothrow));
      if (storage == nullptr) {
        return;
      }

      storage->fileCount = fileCount;
      mFileCount = fileCount;
      mFiles = reinterpret_cast<wxStringRuntime*>(reinterpret_cast<std::uint8_t*>(storage) + sizeof(*storage));
      for (std::uint32_t index = 0; index < mFileCount; ++index) {
        mFiles[index].m_pchData = nullptr;
      }
    }

    void AssignFiles(
      const wxStringRuntime* const files,
      const std::uint32_t fileCount
    )
    {
      if (files == nullptr || fileCount == 0u) {
        return;
      }

      AllocateFileArray(fileCount);
      for (std::uint32_t index = 0; index < mFileCount; ++index) {
        const wchar_t* const sourceText = files[index].c_str();
        const std::size_t sourceLength = std::wcslen(sourceText);
        auto* const copiedText = new (std::nothrow) wchar_t[sourceLength + 1u];
        if (copiedText == nullptr) {
          continue;
        }

        std::wmemcpy(copiedText, sourceText, sourceLength + 1u);
        mFiles[index] = wxStringRuntime::Borrow(copiedText);
      }
    }

    void ReleaseFileArray() noexcept
    {
      if (mFiles != nullptr) {
        for (std::uint32_t index = 0; index < mFileCount; ++index) {
          delete[] mFiles[index].m_pchData;
          mFiles[index].m_pchData = nullptr;
        }

        void* const storage = reinterpret_cast<std::uint8_t*>(mFiles) - sizeof(WxDropFilesArrayStorage);
        ::operator delete(storage);
      }

      mFiles = nullptr;
      mFileCount = 0;
    }
  };

  static_assert(
    offsetof(WxDropFilesEventRuntime, mFileCount) == 0x20,
    "WxDropFilesEventRuntime::mFileCount offset must be 0x20"
  );
  static_assert(
    offsetof(WxDropFilesEventRuntime, mDropPointX) == 0x24,
    "WxDropFilesEventRuntime::mDropPointX offset must be 0x24"
  );
  static_assert(
    offsetof(WxDropFilesEventRuntime, mDropPointY) == 0x28,
    "WxDropFilesEventRuntime::mDropPointY offset must be 0x28"
  );
  static_assert(
    offsetof(WxDropFilesEventRuntime, mFiles) == 0x2C,
    "WxDropFilesEventRuntime::mFiles offset must be 0x2C"
  );
  static_assert(sizeof(WxDropFilesEventRuntime) == 0x30, "WxDropFilesEventRuntime size must be 0x30");

  class WxMouseCaptureChangedEventRuntime final : public wxEventRuntime
  {
  public:
    WxMouseCaptureChangedEventRuntime(
      const std::int32_t eventId,
      const std::int32_t eventType,
      wxWindowMswRuntime* const previousCapture
    )
      : wxEventRuntime(eventId, eventType)
      , mPreviousCapture(previousCapture)
    {}

    WxMouseCaptureChangedEventRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxMouseCaptureChangedEventRuntime(mEventId, mEventType, mPreviousCapture);
      if (clone == nullptr) {
        return nullptr;
      }

      clone->mRefData = mRefData;
      clone->mEventObject = mEventObject;
      clone->mEventTimestamp = mEventTimestamp;
      clone->mCallbackUserData = mCallbackUserData;
      clone->mSkipped = mSkipped;
      clone->mIsCommandEvent = mIsCommandEvent;
      clone->mReserved1E = mReserved1E;
      clone->mReserved1F = mReserved1F;
      return clone;
    }

    wxWindowMswRuntime* mPreviousCapture = nullptr;
  };

  static_assert(
    offsetof(WxMouseCaptureChangedEventRuntime, mPreviousCapture) == 0x20,
    "WxMouseCaptureChangedEventRuntime::mPreviousCapture offset must be 0x20"
  );
  static_assert(
    sizeof(WxMouseCaptureChangedEventRuntime) == 0x24,
    "WxMouseCaptureChangedEventRuntime size must be 0x24"
  );

  [[nodiscard]] std::uintptr_t AllocateSupComFramePseudoHandle() noexcept
  {
    const std::uintptr_t handle = gNextSupComFramePseudoHandle;
    gNextSupComFramePseudoHandle += kSupComFramePseudoHandleStride;
    return handle;
  }

  [[nodiscard]] SupComFrameState* FindSupComFrameState(
    const WSupComFrame* const frame
  ) noexcept
  {
    const auto it = gSupComFrameStateByFrame.find(frame);
    return it != gSupComFrameStateByFrame.end() ? &it->second : nullptr;
  }

  [[nodiscard]] const WxTopLevelWindowRuntimeState* FindWxTopLevelWindowRuntimeState(
    const wxTopLevelWindowRuntime* const window
  ) noexcept
  {
    const auto it = gWxTopLevelWindowRuntimeStateByWindow.find(window);
    return it != gWxTopLevelWindowRuntimeStateByWindow.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxTopLevelWindowRuntimeState& EnsureWxTopLevelWindowRuntimeState(
    const wxTopLevelWindowRuntime* const window
  )
  {
    return gWxTopLevelWindowRuntimeStateByWindow[window];
  }

  [[nodiscard]] WxDialogRuntimeState& EnsureWxDialogRuntimeState(
    const wxDialogRuntime* const dialog
  )
  {
    return gWxDialogRuntimeStateByDialog[dialog];
  }

  [[nodiscard]] WxTreeListRuntimeState& EnsureWxTreeListRuntimeState(
    const wxTreeListCtrlRuntime* const treeControl
  )
  {
    return gWxTreeListRuntimeStateByControl[treeControl];
  }

  [[nodiscard]] const WxTreeListRuntimeState* FindWxTreeListRuntimeState(
    const wxTreeListCtrlRuntime* const treeControl
  ) noexcept
  {
    const auto it = gWxTreeListRuntimeStateByControl.find(treeControl);
    return it != gWxTreeListRuntimeStateByControl.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxTreeListNodeRuntimeState* AllocateTreeListNode(
    WxTreeListRuntimeState& state,
    WxTreeListNodeRuntimeState* const parentNode,
    const msvc8::string& rootText
  )
  {
    auto node = std::make_unique<WxTreeListNodeRuntimeState>();
    node->parent = parentNode;
    node->columnText.resize(3);
    node->columnText[0] = rootText;

    WxTreeListNodeRuntimeState* const rawNode = node.get();
    state.nodeStorage.push_back(std::move(node));
    if (parentNode != nullptr) {
      parentNode->children.push_back(rawNode);
    }
    return rawNode;
  }

  [[nodiscard]] WxTreeListNodeRuntimeState* ResolveTreeListNode(
    const wxTreeItemIdRuntime& item
  ) noexcept
  {
    return static_cast<WxTreeListNodeRuntimeState*>(item.mNode);
  }

  [[nodiscard]] const WxTreeListNodeRuntimeState* ResolveTreeListNodeConst(
    const wxTreeItemIdRuntime& item
  ) noexcept
  {
    return static_cast<const WxTreeListNodeRuntimeState*>(item.mNode);
  }

  [[nodiscard]] const WxWindowBaseRuntimeState* FindWxWindowBaseRuntimeState(
    const wxWindowBase* const window
  ) noexcept
  {
    const auto it = gWxWindowBaseStateByWindow.find(window);
    return it != gWxWindowBaseStateByWindow.end() ? &it->second : nullptr;
  }

  [[nodiscard]] WxWindowBaseRuntimeState& EnsureWxWindowBaseRuntimeState(
    const wxWindowBase* const window
  )
  {
    return gWxWindowBaseStateByWindow[window];
  }

  [[nodiscard]] WxTextCtrlRuntimeState& EnsureWxTextCtrlRuntimeState(
    const wxTextCtrlRuntime* const control
  )
  {
    return gWxTextCtrlStateByControl[control];
  }

  [[nodiscard]] SupComFrameState& EnsureSupComFrameState(
    const WSupComFrame* const frame
  )
  {
    return gSupComFrameStateByFrame[frame];
  }

  class WSupComFrameRuntime final : public WSupComFrame
  {
  public:
    WSupComFrameRuntime(
      const char* const titleUtf8,
      const wxPoint& initialPosition,
      const wxSize& initialClientSize,
      const std::int32_t style
    )
    {
      mPendingMaximizeSync = 0;
      mPersistedMaximizeSync = 0;
      mIsApplicationActive = 0;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.clientWidth = initialClientSize.x > 0 ? initialClientSize.x : 0;
      state.clientHeight = initialClientSize.y > 0 ? initialClientSize.y : 0;
      state.windowX = initialPosition.x;
      state.windowY = initialPosition.y;
      state.windowStyle = style;
      state.pseudoWindowHandle = AllocateSupComFramePseudoHandle();
      state.title = gpg::STR_Utf8ToWide(titleUtf8 != nullptr ? titleUtf8 : "");
      state.name.assign(kSupComFrameWindowName);
      state.iconResourceName.assign(kSupComFrameIconResourceName);
      state.iconResourceAssigned = true;
    }

    bool Destroy() override
    {
      gWxTopLevelWindowRuntimeStateByWindow.erase(this);
      gWxWindowBaseStateByWindow.erase(this);
      gSupComFrameStateByFrame.erase(this);
      delete this;
      return true;
    }

    bool Show(
      const bool show
    ) override
    {
      EnsureSupComFrameState(this).visible = show;
      return true;
    }

    void SetTitle(
      const wxStringRuntime& title
    ) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.title.assign(title.c_str());
    }

    void SetName(
      const wxStringRuntime& name
    ) override
    {
      wxWindowBase::SetName(name);
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.name.assign(name.c_str());
    }

    void SetWindowStyleFlag(
      const long style
    ) override
    {
      EnsureSupComFrameState(this).windowStyle = static_cast<std::int32_t>(style);
    }

    [[nodiscard]] long GetWindowStyleFlag() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr ? state->windowStyle : 0;
    }

    void SetSizeHints(
      const std::int32_t minWidth,
      const std::int32_t minHeight,
      const std::int32_t maxWidth,
      const std::int32_t maxHeight,
      const std::int32_t incWidth,
      const std::int32_t incHeight
    ) override
    {
      (void)maxWidth;
      (void)maxHeight;
      (void)incWidth;
      (void)incHeight;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.minWidth = minWidth > 0 ? minWidth : 0;
      state.minHeight = minHeight > 0 ? minHeight : 0;
      if (state.clientWidth < state.minWidth) {
        state.clientWidth = state.minWidth;
      }
      if (state.clientHeight < state.minHeight) {
        state.clientHeight = state.minHeight;
      }
    }

    void SetFocus() override
    {
      EnsureSupComFrameState(this).focused = true;
    }

    [[nodiscard]] unsigned long GetHandle() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr ? static_cast<unsigned long>(state->pseudoWindowHandle) : 0u;
    }

    void DoGetClientSize(
      std::int32_t* const outWidth,
      std::int32_t* const outHeight
    ) const override
    {
      if (outWidth != nullptr) {
        *outWidth = 0;
      }
      if (outHeight != nullptr) {
        *outHeight = 0;
      }

      const SupComFrameState* const state = FindSupComFrameState(this);
      if (state == nullptr) {
        return;
      }

      if (outWidth != nullptr) {
        *outWidth = state->clientWidth;
      }
      if (outHeight != nullptr) {
        *outHeight = state->clientHeight;
      }
    }

    void DoSetClientSize(
      const std::int32_t width,
      const std::int32_t height
    ) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      const std::int32_t requestedWidth = width > 0 ? width : 0;
      const std::int32_t requestedHeight = height > 0 ? height : 0;
      state.clientWidth = requestedWidth > state.minWidth ? requestedWidth : state.minWidth;
      state.clientHeight = requestedHeight > state.minHeight ? requestedHeight : state.minHeight;
    }

    void DoGetPosition(
      std::int32_t* const x,
      std::int32_t* const y
    ) const override
    {
      if (x != nullptr) {
        *x = 0;
      }
      if (y != nullptr) {
        *y = 0;
      }

      const SupComFrameState* const state = FindSupComFrameState(this);
      if (state == nullptr) {
        return;
      }

      if (x != nullptr) {
        *x = state->windowX;
      }
      if (y != nullptr) {
        *y = state->windowY;
      }
    }

    void DoSetSize(
      const std::int32_t x,
      const std::int32_t y,
      const std::int32_t width,
      const std::int32_t height,
      const std::int32_t sizeFlags
    ) override
    {
      (void)sizeFlags;

      SupComFrameState& state = EnsureSupComFrameState(this);
      state.windowX = x;
      state.windowY = y;
      DoSetClientSize(width, height);
    }

    void Maximize(
      const bool maximize
    ) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.maximized = maximize;
      mPendingMaximizeSync = maximize ? 1 : 0;
      mPersistedMaximizeSync = maximize ? 1 : 0;
    }

    void Iconize(
      const bool iconize
    ) override
    {
      EnsureSupComFrameState(this).iconized = iconize;
    }

    [[nodiscard]] bool IsMaximized() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr && state->maximized;
    }

    [[nodiscard]] bool IsIconized() const override
    {
      const SupComFrameState* const state = FindSupComFrameState(this);
      return state != nullptr && state->iconized;
    }

    void SetIcon(
      const void* const icon
    ) override
    {
      SupComFrameState& state = EnsureSupComFrameState(this);
      state.iconResourceAssigned = icon != nullptr;
      if (state.iconResourceAssigned) {
        state.iconResourceName.assign(kSupComFrameIconResourceName);
      } else {
        state.iconResourceName.clear();
      }
    }

    void SetIcons(
      const void* const iconBundle
    ) override
    {
      SetIcon(iconBundle);
    }
  };

  struct DwordLaneRuntimeView
  {
    std::uint32_t lane00 = 0;
  };

  static_assert(offsetof(DwordLaneRuntimeView, lane00) == 0x0, "DwordLaneRuntimeView::lane00 offset must be 0x0");
  static_assert(sizeof(DwordLaneRuntimeView) == 0x4, "DwordLaneRuntimeView size must be 0x4");

  /**
   * Address: 0x004A3670 (FUN_004A3670)
   *
   * What it does:
   * Returns the leading 32-bit lane from one unknown runtime pod view.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadRuntimeDwordLaneA(
    const DwordLaneRuntimeView* const view
  ) noexcept
  {
    return view->lane00;
  }

  /**
   * Address: 0x004A3680 (FUN_004A3680)
   *
   * What it does:
   * Returns the leading 32-bit lane from one unknown runtime pod view.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ReadRuntimeDwordLaneB(
    const DwordLaneRuntimeView* const view
  ) noexcept
  {
    return view->lane00;
  }

  struct FourDwordBlockRuntimeView
  {
    std::int32_t lane00 = 0;
    std::int32_t lane04 = 0;
    std::int32_t lane08 = 0;
    std::int32_t lane0C = 0;
  };

  static_assert(sizeof(FourDwordBlockRuntimeView) == 0x10, "FourDwordBlockRuntimeView size must be 0x10");

  /**
   * Address: 0x004A36D0 (FUN_004A36D0)
   *
   * What it does:
   * Clears one four-dword runtime block used by wx region rectangle vectors.
   */
  [[maybe_unused]] void ClearFourDwordBlock(
    FourDwordBlockRuntimeView* const view
  ) noexcept
  {
    view->lane00 = 0;
    view->lane04 = 0;
    view->lane08 = 0;
    view->lane0C = 0;
  }

  class SplashScreenRuntimeImpl final : public moho::SplashScreenRuntime
  {
  public:
    SplashScreenRuntimeImpl(
      const msvc8::string& imagePath,
      const wxSize& size
    )
      : mImagePath(imagePath)
      , mSize(size)
    {}

    void GetClassInfo() override {}

    void DeleteObject(
      const std::uint32_t flags
    ) override
    {
      if ((flags & 1u) != 0u) {
        delete this;
      }
    }

  private:
    msvc8::string mImagePath;
    wxSize mSize{};
  };
} // namespace

/**
 * Address: 0x009ACE50 (FUN_009ACE50, wxENTER_CRIT_SECT)
 *
 * What it does:
 * Enters one Win32 critical-section lane.
 */
void wxENTER_CRIT_SECT(
  _RTL_CRITICAL_SECTION* const criticalSection
)
{
  ::EnterCriticalSection(criticalSection);
}

/**
 * Address: 0x009ACE60 (FUN_009ACE60, wxLEAVE_CRIT_SECT)
 *
 * What it does:
 * Leaves one Win32 critical-section lane.
 */
void wxLEAVE_CRIT_SECT(
  _RTL_CRITICAL_SECTION* const criticalSection
)
{
  ::LeaveCriticalSection(criticalSection);
}

/**
 * Address: 0x009AD330 (FUN_009AD330, wxThread::IsMain)
 *
 * What it does:
 * Returns whether the current Win32 thread matches the stored wx main-thread id.
 */
bool wxThreadIsMain()
{
  return ::GetCurrentThreadId() == gs_idMainThread;
}

/**
 * Address: 0x009AD660 (FUN_009AD660, wxGuiOwnedByMainThread)
 *
 * What it does:
 * Returns the wx GUI-ownership flag managed by the GUI mutex helpers.
 */
bool wxGuiOwnedByMainThread()
{
  EnsureGuiMutexRuntimeInitialized();
  return gs_bGuiOwnedByMainThread != 0;
}

/**
 * Address: 0x009AD670 (FUN_009AD670, wxWakeUpMainThread)
 *
 * What it does:
 * Posts one wake-up message (`WM_NULL`) to the stored wx main-thread id.
 */
bool wxWakeUpMainThread()
{
  return ::PostThreadMessageW(gs_idMainThread, 0u, 0u, 0) != FALSE;
}

/**
 * Address: 0x009ADC20 (FUN_009ADC20, wxMutexGuiLeave)
 *
 * What it does:
 * Releases GUI ownership for the calling lane and unlocks wx GUI/waiting
 * critical sections with the original runtime ordering.
 */
void wxMutexGuiLeave()
{
  _RTL_CRITICAL_SECTION* const waitingForGuiCriticalSection = WaitingForGuiCriticalSection();
  wxENTER_CRIT_SECT(waitingForGuiCriticalSection);

  if (wxThreadIsMain()) {
    gs_bGuiOwnedByMainThread = 0;
  } else {
    --gs_nWaitingForGui;
    (void)wxWakeUpMainThread();
  }

  wxLEAVE_CRIT_SECT(GuiCriticalSection());
  wxLEAVE_CRIT_SECT(waitingForGuiCriticalSection);
}

/**
 * Address: 0x009ADC70 (FUN_009ADC70, wxMutexGuiLeaveOrEnter)
 *
 * What it does:
 * Reconciles GUI ownership against waiting-thread state, leaving or entering
 * the wx GUI critical section as required by the original runtime contract.
 */
void wxMutexGuiLeaveOrEnter()
{
  _RTL_CRITICAL_SECTION* const waitingForGuiCriticalSection = WaitingForGuiCriticalSection();
  wxENTER_CRIT_SECT(waitingForGuiCriticalSection);

  const bool guiOwnedByMainThread = wxGuiOwnedByMainThread();
  if (gs_nWaitingForGui != 0) {
    if (guiOwnedByMainThread) {
      wxMutexGuiLeave();
    }
  } else if (!guiOwnedByMainThread) {
    wxENTER_CRIT_SECT(GuiCriticalSection());
    gs_bGuiOwnedByMainThread = 1;
    wxLEAVE_CRIT_SECT(waitingForGuiCriticalSection);
    return;
  }

  wxLEAVE_CRIT_SECT(waitingForGuiCriticalSection);
}

/**
 * Address: 0x009C7540 (FUN_009C7540, wxGetOsVersion)
 *
 * What it does:
 * Caches Win32 platform-id and major/minor version lanes and returns the wx
 * OS-family enum value.
 */
int wxGetOsVersion(
  int* const majorVsn,
  int* const minorVsn
)
{
  int result = gWxGetOsVersionCache;
  if (gWxGetOsVersionCache == -1) {
    OSVERSIONINFOW versionInformation{};
    gWxGetOsVersionCache = 15;
    versionInformation.dwOSVersionInfoSize = sizeof(versionInformation);
#pragma warning(push)
#pragma warning(disable : 4996)
    const BOOL hasVersionInfo = ::GetVersionExW(&versionInformation);
#pragma warning(pop)
    if (hasVersionInfo != 0) {
      gWxGetOsVersionMinor = static_cast<int>(versionInformation.dwMinorVersion);
      gWxGetOsVersionMajor = static_cast<int>(versionInformation.dwMajorVersion);
      if (versionInformation.dwPlatformId == 0) {
        result = 19;
        gWxGetOsVersionCache = result;
      } else if (versionInformation.dwPlatformId == 1) {
        result = 20;
        gWxGetOsVersionCache = result;
      } else if (versionInformation.dwPlatformId == 2) {
        result = 18;
        gWxGetOsVersionCache = result;
      } else {
        result = gWxGetOsVersionCache;
      }
    } else {
      result = gWxGetOsVersionCache;
    }
  }

  if (majorVsn != nullptr && gWxGetOsVersionMajor != -1) {
    *majorVsn = gWxGetOsVersionMajor;
  }
  if (minorVsn != nullptr && gWxGetOsVersionMinor != -1) {
    *minorVsn = gWxGetOsVersionMinor;
  }
  return result;
}

/**
 * Address: 0x00962900 (FUN_00962900, wxLogDebug)
 *
 * What it does:
 * Preserves wx debug-log callsites as a no-op lane.
 */
void wxLogDebug(
  ...
)
{}

/**
 * Address: 0x009C7BB0 (FUN_009C7BB0, wxBeginBusyCursor)
 *
 * What it does:
 * Increments busy-cursor nesting depth and, on first entry, swaps the active
 * Win32 cursor to the provided wx cursor handle (or null cursor when refdata
 * is absent), while saving the previous cursor lane.
 */
void wxBeginBusyCursor(wxCursor* const cursor)
{
  if (gs_wxBusyCursorCount++ != 0) {
    return;
  }

  const auto* const objectView = reinterpret_cast<const WxObjectRuntimeView*>(cursor);
  const auto* const refDataView = reinterpret_cast<const WxCursorRefDataRuntimeView*>(objectView->refData);
  if (refDataView != nullptr) {
    gs_wxBusyCursor = reinterpret_cast<HCURSOR>(refDataView->nativeCursorHandle);
    gs_wxBusyCursorOld = ::SetCursor(gs_wxBusyCursor);
    return;
  }

  gs_wxBusyCursor = nullptr;
  gs_wxBusyCursorOld = ::SetCursor(nullptr);
}

/**
 * Address: 0x009CD1D0 (FUN_009CD1D0, wx::copystring)
 *
 * What it does:
 * Allocates one heap-owned UTF-16 copy of the input string and falls back to
 * an empty literal when the source pointer is null.
 */
wchar_t* wx::copystring(
  const wchar_t* const text
)
{
  const wchar_t* const source = (text != nullptr) ? text : L"";
  std::size_t length = 0;
  while (source[length] != L'\0') {
    ++length;
  }

  auto* const copy = static_cast<wchar_t*>(::operator new((length + 1u) * sizeof(wchar_t)));
  std::memcpy(copy, source, (length + 1u) * sizeof(wchar_t));
  return copy;
}

void* wxTopLevelWindowRootRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3690 (FUN_004A3690)
 * Mangled: ??0wxClientData@@QAE@@Z
 *
 * What it does:
 * Constructs one `wxClientData` runtime lane.
 */
wxClientDataRuntime::wxClientDataRuntime()
{
  ResetRuntimeVTable();
}

/**
 * Address: 0x004A36A0 (FUN_004A36A0)
 *
 * What it does:
 * Rebinds this object to the `wxClientData` runtime vtable lane.
 */
void wxClientDataRuntime::ResetRuntimeVTable() noexcept {}

/**
 * Address: 0x004A36B0 (FUN_004A36B0)
 *
 * What it does:
 * Implements the deleting-dtor thunk lane for `wxClientData`.
 */
wxClientDataRuntime* wxClientDataRuntime::DeleteWithFlag(
  wxClientDataRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->ResetRuntimeVTable();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A3710 (FUN_004A3710)
 * Mangled: ??0wxTopLevelWindowMSW@@QAE@@Z
 *
 * What it does:
 * Constructs one top-level-window runtime base lane and resets fullscreen
 * state bookkeeping.
 */
wxTopLevelWindowRuntime::wxTopLevelWindowRuntime()
{
  WxTopLevelWindowRuntimeState& state = EnsureWxTopLevelWindowRuntimeState(this);
  state.fsOldX = 0;
  state.fsOldY = 0;
  state.fsOldWidth = 0;
  state.fsOldHeight = 0;
  ResetTopLevelFlag34();
}

/**
 * Address: 0x0098C280 (FUN_0098C280, wxTopLevelWindowMSW::Show)
 * Mangled: ?Show@wxTopLevelWindowMSW@@UAE_N_N@Z
 *
 * What it does:
 * Runs base visibility transition and raises this window (or parent when
 * hiding) when native-handle lanes are present in runtime state.
 */
bool wxTopLevelWindowRuntime::Show(
  const bool show
)
{
  if (!wxWindowBase::Show(show)) {
    return false;
  }

  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  if (show) {
    if (state != nullptr && state->nativeHandle != 0u) {
      ::BringWindowToTop(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(state->nativeHandle)));
    }
  } else if (state != nullptr && state->parentWindow != nullptr) {
    const WxWindowBaseRuntimeState* const parentState = FindWxWindowBaseRuntimeState(state->parentWindow);
    if (parentState != nullptr && parentState->nativeHandle != 0u) {
      ::BringWindowToTop(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(parentState->nativeHandle)));
    }
  }

  return true;
}

/**
 * Address: 0x004A36E0 (FUN_004A36E0)
 *
 * What it does:
 * Resets one top-level-window runtime flag lane.
 */
void wxTopLevelWindowRuntime::ResetTopLevelFlag34() noexcept
{
  EnsureWxTopLevelWindowRuntimeState(this).flag34 = 0;
}

/**
 * Address: 0x004A36F0 (FUN_004A36F0)
 * Mangled: ?IsTopLevel@wxTopLevelWindowBase@@UBE_NXZ
 *
 * What it does:
 * Reports this runtime lane as a top-level wx window.
 */
bool wxTopLevelWindowRuntime::IsTopLevel() const
{
  return true;
}

/**
 * Address: 0x004A3700 (FUN_004A3700)
 * Mangled: ?IsOneOfBars@wxTopLevelWindowBase@@MBE_NPBVwxWindow@@@Z
 *
 * What it does:
 * Base implementation reports the queried window as not one of frame bars.
 */
bool wxTopLevelWindowRuntime::IsOneOfBars(
  const void* const window
) const
{
  (void)window;
  return false;
}

/**
 * Address: 0x004A3770 (FUN_004A3770)
 * Mangled: ?IsFullScreen@wxTopLevelWindowMSW@@UBE_NXZ
 *
 * What it does:
 * Returns one cached fullscreen-visible flag.
 */
bool wxTopLevelWindowRuntime::IsFullScreen() const
{
  const WxTopLevelWindowRuntimeState* const state = FindWxTopLevelWindowRuntimeState(this);
  return state != nullptr && state->flag34 != 0;
}

/**
 * Address: 0x004A3780 (FUN_004A3780)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for top-level-window runtime
 * lanes.
 */
wxTopLevelWindowRuntime* wxTopLevelWindowRuntime::DeleteWithFlag(
  wxTopLevelWindowRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxTopLevelWindowRuntimeStateByWindow.erase(object);
  object->~wxTopLevelWindowRuntime();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A37A0 (FUN_004A37A0)
 * Mangled: ??0wxTopLevelWindow@@QAE@@Z
 *
 * What it does:
 * Constructs one `wxTopLevelWindow` runtime layer and reapplies base
 * top-level init.
 */
wxTopLevelWindowRootRuntime::wxTopLevelWindowRootRuntime()
  : wxTopLevelWindowRuntime()
{
  ResetTopLevelFlag34();
}

/**
 * Address: 0x004A3800 (FUN_004A3800)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for `wxTopLevelWindow`.
 */
wxTopLevelWindowRootRuntime* wxTopLevelWindowRootRuntime::DeleteWithFlag(
  wxTopLevelWindowRootRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  return reinterpret_cast<wxTopLevelWindowRootRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(reinterpret_cast<wxTopLevelWindowRuntime*>(object), deleteFlags)
  );
}

/**
 * Address: 0x004A3820 (FUN_004A3820)
 *
 * What it does:
 * Runs the non-deleting top-level-window teardown thunk.
 */
wxTopLevelWindowRootRuntime* wxTopLevelWindowRootRuntime::DestroyWithoutDelete(
  wxTopLevelWindowRootRuntime* const object
) noexcept
{
  return DeleteWithFlag(object, 0);
}

void wxControlContainerRuntime::Initialize(
  const bool acceptsFocusRecursion
) noexcept
{
  mAcceptsFocusRecursion = acceptsFocusRecursion ? 1 : 0;
}

void* wxDialogRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3860 (FUN_004A3860)
 * Mangled: ??0wxDialogBase@@QAE@@Z
 *
 * What it does:
 * Builds one dialog-base runtime lane, initializes control-container
 * storage, then runs dialog-base init.
 */
wxDialogBaseRuntime::wxDialogBaseRuntime()
  : wxTopLevelWindowRootRuntime()
{
  mControlContainer.Initialize(false);
  InitRuntime();
}

void wxDialogBaseRuntime::InitRuntime() noexcept {}

/**
 * Address: 0x004A38C0 (FUN_004A38C0)
 *
 * What it does:
 * Runs non-deleting teardown for dialog-base runtime lanes.
 */
wxDialogBaseRuntime* wxDialogBaseRuntime::DestroyWithoutDelete(
  wxDialogBaseRuntime* const object
) noexcept
{
  return reinterpret_cast<wxDialogBaseRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(reinterpret_cast<wxTopLevelWindowRuntime*>(object), 0)
  );
}

/**
 * Address: 0x004A38D0 (FUN_004A38D0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for dialog-base runtime lanes.
 */
wxDialogBaseRuntime* wxDialogBaseRuntime::DeleteWithFlag(
  wxDialogBaseRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxDialogRuntimeStateByDialog.erase(reinterpret_cast<const wxDialogRuntime*>(object));
  return reinterpret_cast<wxDialogBaseRuntime*>(
    wxTopLevelWindowRuntime::DeleteWithFlag(reinterpret_cast<wxTopLevelWindowRuntime*>(object), deleteFlags)
  );
}

/**
 * Address: 0x0098B870 (FUN_0098B870)
 * Mangled: ??0wxDialog@@QAE@XZ
 *
 * What it does:
 * Builds one dialog runtime lane and initializes default dialog state.
 */
wxDialogRuntime::wxDialogRuntime()
  : wxDialogBaseRuntime()
{
  (void)EnsureWxDialogRuntimeState(this);
}

/**
 * Address: 0x004A3900 (FUN_004A3900)
 * Mangled: ??0wxDialog@@QAE@PAVwxWindow@@HABVwxString@@ABVwxPoint@@ABVwxSize@@J1@Z
 *
 * What it does:
 * Builds one dialog runtime lane, then applies create/init arguments.
 */
wxDialogRuntime::wxDialogRuntime(
  void* const parentWindow,
  const std::int32_t windowId,
  const wxStringRuntime& title,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxStringRuntime& name
)
  : wxDialogBaseRuntime()
{
  WxDialogRuntimeState& state = EnsureWxDialogRuntimeState(this);
  state.parentWindow = parentWindow;
  state.windowId = windowId;
  state.position = position;
  state.size = size;
  state.style = style;
  state.title.assign(title.c_str());
  state.name.assign(name.c_str());
}

/**
 * Address: 0x004A3970 (FUN_004A3970)
 * Mangled: ?GetClassInfo@wxDialog@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for dialog runtime RTTI checks.
 */
void* wxDialogRuntime::GetClassInfo() const
{
  return sm_classInfo;
}

/**
 * Address: 0x004A3980 (FUN_004A3980)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for dialog runtime lanes.
 */
wxDialogRuntime* wxDialogRuntime::DeleteWithFlag(
  wxDialogRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxDialogRuntimeStateByDialog.erase(object);
  return reinterpret_cast<wxDialogRuntime*>(
    wxDialogBaseRuntime::DeleteWithFlag(reinterpret_cast<wxDialogBaseRuntime*>(object), deleteFlags)
  );
}

/**
 * Address: 0x004A39A0 (FUN_004A39A0)
 *
 * What it does:
 * Clears this item-id to the null value.
 */
void wxTreeItemIdRuntime::Reset() noexcept
{
  mNode = nullptr;
}

/**
 * Address: 0x004A39B0 (FUN_004A39B0)
 *
 * What it does:
 * Reports whether this item-id currently references a valid node.
 */
bool wxTreeItemIdRuntime::IsValid() const noexcept
{
  return mNode != nullptr;
}

/**
 * Address: 0x004A39C0 (FUN_004A39C0)
 *
 * What it does:
 * Constructs one tree-item payload lane with null item data.
 */
wxTreeItemDataRuntime::wxTreeItemDataRuntime()
  : wxClientDataRuntime()
{
  mPayload = nullptr;
}

/**
 * Address: 0x004A39F0 (FUN_004A39F0)
 *
 * What it does:
 * Rebinds this object to the `wxClientData` base vtable lane.
 */
void wxTreeItemDataRuntime::ResetClientDataBaseVTable() noexcept
{
  ResetRuntimeVTable();
}

/**
 * Address: 0x004A39D0 (FUN_004A39D0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-item payload lanes.
 */
wxTreeItemDataRuntime* wxTreeItemDataRuntime::DeleteWithFlag(
  wxTreeItemDataRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->ResetClientDataBaseVTable();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004A3A00 (FUN_004A3A00)
 *
 * What it does:
 * Copies the primary tree-item-id lane into `outItem`.
 */
void wxTreeEventRuntime::GetItem(
  wxTreeItemIdRuntime* const outItem
) const noexcept
{
  if (outItem != nullptr) {
    *outItem = mItem;
  }
}

/**
 * Address: 0x004A3A10 (FUN_004A3A10)
 *
 * What it does:
 * Returns the label storage lane for this tree event.
 */
wxStringRuntime* wxTreeEventRuntime::GetLabelStorage() noexcept
{
  return &mLabel;
}

/**
 * Address: 0x004A3A20 (FUN_004A3A20)
 *
 * What it does:
 * Returns the edit-cancelled flag lane for this tree event.
 */
bool wxTreeEventRuntime::IsEditCancelled() const noexcept
{
  return mEditCancelled != 0;
}

/**
 * Address: 0x004A3A30 (FUN_004A3A30)
 *
 * What it does:
 * Initializes one tree-list column descriptor from title/width/align and
 * owner lane arguments.
 */
wxTreeListColumnInfoRuntime::wxTreeListColumnInfoRuntime(
  const wxStringRuntime& title,
  const std::int32_t width,
  void* const ownerTreeControl,
  const std::uint8_t shown,
  const std::uint8_t alignment,
  const std::int32_t userData
)
{
  mRefData = nullptr;
  mText = wxStringRuntime::Borrow(L"");
  mShown = shown;
  mAlignment = alignment;
  mUserData = userData;
  mText = title;
  mWidth = width;
  mImageIndex = -1;
  mOwnerTreeControl = ownerTreeControl;
}

/**
 * Address: 0x004A3AC0 (FUN_004A3AC0)
 *
 * What it does:
 * Runs non-deleting teardown for one tree-list column descriptor lane.
 */
void wxTreeListColumnInfoRuntime::DestroyWithoutDelete() noexcept
{
  mRefData = nullptr;
  mOwnerTreeControl = nullptr;
}

/**
 * Address: 0x004A3B30 (FUN_004A3B30)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-list column descriptors.
 */
wxTreeListColumnInfoRuntime* wxTreeListColumnInfoRuntime::DeleteWithFlag(
  wxTreeListColumnInfoRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  object->DestroyWithoutDelete();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

void* wxTreeListCtrlRuntime::sm_classInfo[1] = {nullptr};

/**
 * Address: 0x004A3B50 (FUN_004A3B50)
 * Mangled: ??0wxTreeListCtrl@@QAE@PAVwxWindow@@HABVwxPoint@@ABVwxSize@@JABVwxValidator@@ABVwxString@@@Z
 *
 * What it does:
 * Initializes one tree-list control runtime lane with parent/style/name
 * creation arguments.
 */
wxTreeListCtrlRuntime::wxTreeListCtrlRuntime(
  wxWindowBase* const parentWindow,
  const std::int32_t windowId,
  const wxPoint& position,
  const wxSize& size,
  const long style,
  const wxStringRuntime& name
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  state.parentWindow = parentWindow;
  state.windowId = windowId;
  state.position = position;
  state.size = size;
  state.style = style;
  state.name.assign(name.c_str());
}

/**
 * Address: 0x004A3BD0 (FUN_004A3BD0)
 *
 * What it does:
 * Runs non-deleting teardown for one tree-list control runtime lane.
 */
wxTreeListCtrlRuntime* wxTreeListCtrlRuntime::DestroyWithoutDelete(
  wxTreeListCtrlRuntime* const object
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gWxTreeListRuntimeStateByControl.erase(object);
  return object;
}

/**
 * Address: 0x004A3BE0 (FUN_004A3BE0)
 * Mangled: ?AddColumn@wxTreeListCtrl@@QAEXABVwxString@@I_NW4wxTreeListColumnAlign@@@Z
 *
 * What it does:
 * Appends one tree-list column descriptor to this control.
 */
void wxTreeListCtrlRuntime::AddColumn(
  const wxStringRuntime& title,
  const std::uint32_t width,
  const bool shown,
  const std::uint8_t alignment
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  state.columns.emplace_back(title, static_cast<std::int32_t>(width), this, shown ? 1u : 0u, alignment, 0);
}

/**
 * Address: 0x004A3C50 (FUN_004A3C50)
 * Mangled: ?GetWindowStyleFlag@wxTreeListCtrl@@UBEJXZ
 *
 * What it does:
 * Returns the cached window-style flags for this tree-list control.
 */
long wxTreeListCtrlRuntime::GetWindowStyleFlag() const
{
  const WxTreeListRuntimeState* const state = FindWxTreeListRuntimeState(this);
  return state != nullptr ? state->style : 0;
}

/**
 * Address: 0x004A3C70 (FUN_004A3C70)
 * Mangled: ?GetClassInfo@wxTreeListCtrl@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for tree-list runtime RTTI checks.
 */
void* wxTreeListCtrlRuntime::GetClassInfo() const
{
  return sm_classInfo;
}

/**
 * Address: 0x004A3C80 (FUN_004A3C80)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for tree-list control runtime
 * lanes.
 */
wxTreeListCtrlRuntime* wxTreeListCtrlRuntime::DeleteWithFlag(
  wxTreeListCtrlRuntime* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  DestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

wxTreeItemIdRuntime wxTreeListCtrlRuntime::AddRoot(
  const wxStringRuntime& text
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  wxTreeItemIdRuntime item{};
  const msvc8::string rootText = text.ToUtf8();
  state.rootNode = AllocateTreeListNode(state, nullptr, rootText);
  item.mNode = state.rootNode;
  return item;
}

wxTreeItemIdRuntime wxTreeListCtrlRuntime::AppendItem(
  const wxTreeItemIdRuntime& parentItem,
  const wxStringRuntime& text
)
{
  WxTreeListRuntimeState& state = EnsureWxTreeListRuntimeState(this);
  wxTreeItemIdRuntime item{};

  WxTreeListNodeRuntimeState* const parentNode = ResolveTreeListNode(parentItem);
  if (parentNode == nullptr) {
    return AddRoot(text);
  }

  const msvc8::string nodeText = text.ToUtf8();
  item.mNode = AllocateTreeListNode(state, parentNode, nodeText);
  return item;
}

void wxTreeListCtrlRuntime::Expand(
  const wxTreeItemIdRuntime& item
) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->isExpanded = true;
}

void wxTreeListCtrlRuntime::Collapse(
  const wxTreeItemIdRuntime& item
) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->isExpanded = false;
}

bool wxTreeListCtrlRuntime::IsExpanded(
  const wxTreeItemIdRuntime& item
) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  return node != nullptr && node->isExpanded;
}

bool wxTreeListCtrlRuntime::HasChildren(
  const wxTreeItemIdRuntime& item
) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  if (node == nullptr) {
    return false;
  }

  return node->hasChildrenFlag || !node->children.empty();
}

void wxTreeListCtrlRuntime::SortChildren(
  const wxTreeItemIdRuntime& item
)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr || node->children.size() < 2u) {
    return;
  }

  std::stable_sort(
    node->children.begin(),
    node->children.end(),
    [](const WxTreeListNodeRuntimeState* const lhs, const WxTreeListNodeRuntimeState* const rhs) {
    static const msvc8::string kEmptyText{};
    const msvc8::string& lhsText = (lhs != nullptr && !lhs->columnText.empty()) ? lhs->columnText[0] : kEmptyText;
    const msvc8::string& rhsText = (rhs != nullptr && !rhs->columnText.empty()) ? rhs->columnText[0] : kEmptyText;
    return lhsText < rhsText;
  }
  );
}

void wxTreeListCtrlRuntime::SetItemData(
  const wxTreeItemIdRuntime& item,
  wxTreeItemDataRuntime* const itemData
)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->itemData = itemData;
}

wxTreeItemDataRuntime* wxTreeListCtrlRuntime::GetItemData(
  const wxTreeItemIdRuntime& item
) const noexcept
{
  const WxTreeListNodeRuntimeState* const node = ResolveTreeListNodeConst(item);
  return node != nullptr ? node->itemData : nullptr;
}

void wxTreeListCtrlRuntime::SetItemHasChildren(
  const wxTreeItemIdRuntime& item,
  const bool hasChildren
) noexcept
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }
  node->hasChildrenFlag = hasChildren;
}

void wxTreeListCtrlRuntime::SetItemText(
  const wxTreeItemIdRuntime& item,
  const std::uint32_t column,
  const wxStringRuntime& text
)
{
  WxTreeListNodeRuntimeState* const node = ResolveTreeListNode(item);
  if (node == nullptr) {
    return;
  }

  if (node->columnText.size() <= column) {
    node->columnText.resize(static_cast<std::size_t>(column) + 1u);
  }
  node->columnText[static_cast<std::size_t>(column)] = text.ToUtf8();
}

/**
 * Address: 0x004A37F0 (FUN_004A37F0)
 * Mangled: ?GetClassInfo@wxFrameBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the shared class-info lane used by frame/dialog/top-level
 * `GetClassInfo` slot-0 entries.
 */
void** WX_FrameBaseGetClassInfo() noexcept
{
  return wxTopLevelWindowRootRuntime::sm_classInfo;
}

/**
 * Address: 0x0099E8A0 (FUN_0099E8A0)
 *
 * What it does:
 * Runs non-deleting frame-runtime teardown for frame-derived windows.
 */
wxTopLevelWindowRuntime* WX_FrameDestroyWithoutDelete(
  wxTopLevelWindowRuntime* const frame
) noexcept
{
  if (frame == nullptr) {
    return nullptr;
  }

  // Binary path sets the frame "destroyed" bit before delegating to shared
  // frame-base teardown.
  EnsureWxWindowBaseRuntimeState(frame).bitfields |= 0x8u;
  return wxTopLevelWindowRuntime::DeleteWithFlag(frame, 0u);
}

/**
 * Address: 0x0042B770 (FUN_0042B770)
 * Mangled: ?GetClassInfo@wxWindowBase@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxWindowBase runtime RTTI checks.
 */
void* wxWindowBase::GetClassInfo() const
{
  return gWxWindowBaseClassInfoTable;
}

/**
 * Address: 0x00968C10 (FUN_00968C10, wxFindWinFromHandle)
 *
 * What it does:
 * Resolves one native HWND lane through `wxWinHandleHash` and returns the
 * associated wxWindow runtime pointer when present.
 */
wxWindowMswRuntime* wxFindWinFromHandle(
  const int nativeHandle
)
{
  if (wxWinHandleHash == nullptr) {
    return nullptr;
  }

  void* const hashEntry =
    wxWinHandleHash->Get(nativeHandle, reinterpret_cast<void*>(static_cast<std::uintptr_t>(nativeHandle)));
  if (hashEntry == nullptr) {
    return nullptr;
  }

  const auto* const entryRuntime = static_cast<const WxWindowHandleHashEntryRuntime*>(hashEntry);
  return entryRuntime->window;
}

/**
 * Address: 0x00968B10 (FUN_00968B10, wxWindow::UnpackCommand)
 *
 * What it does:
 * Splits command `wParam` into low/high word lanes and forwards control
 * handle lane from `lParam`.
 */
unsigned short wxWindowMswRuntime::UnpackCommand(
  const unsigned int packedWord,
  const int controlHandle,
  unsigned short* const outCommandId,
  unsigned int* const outControlHandle,
  unsigned short* const outNotificationCode
)
{
  const unsigned short commandId = static_cast<unsigned short>(packedWord & 0xFFFFu);
  const unsigned short notificationCode = static_cast<unsigned short>((packedWord >> 16u) & 0xFFFFu);
  if (outCommandId != nullptr) {
    *outCommandId = commandId;
  }
  if (outControlHandle != nullptr) {
    *outControlHandle = static_cast<unsigned int>(controlHandle);
  }
  if (outNotificationCode != nullptr) {
    *outNotificationCode = notificationCode;
  }
  return notificationCode;
}

/**
 * Address: 0x00968B40 (FUN_00968B40, wxWindow::UnpackActivate)
 *
 * What it does:
 * Splits activation packed word into low/high word lanes and forwards the
 * native window handle lane.
 */
unsigned int* wxWindowMswRuntime::UnpackActivate(
  const int packedWord,
  const int nativeWindowHandle,
  unsigned short* const outState,
  unsigned short* const outMinimized,
  unsigned int* const outNativeWindowHandle
)
{
  if (outState != nullptr) {
    *outState = static_cast<unsigned short>(packedWord & 0xFFFF);
  }
  if (outMinimized != nullptr) {
    *outMinimized = static_cast<unsigned short>((static_cast<unsigned int>(packedWord) >> 16u) & 0xFFFFu);
  }
  if (outNativeWindowHandle != nullptr) {
    *outNativeWindowHandle = static_cast<unsigned int>(nativeWindowHandle);
  }
  return outNativeWindowHandle;
}

/**
 * Address: 0x00968B70 (FUN_00968B70, wxWindow::UnpackScroll)
 *
 * What it does:
 * Splits scroll packed word into request/position lanes and forwards the
 * native scroll-bar handle lane.
 */
unsigned int* wxWindowMswRuntime::UnpackScroll(
  const int packedWord,
  const int scrollBarHandle,
  unsigned short* const outRequest,
  unsigned short* const outPosition,
  unsigned int* const outScrollBarHandle
)
{
  if (outRequest != nullptr) {
    *outRequest = static_cast<unsigned short>(packedWord & 0xFFFF);
  }
  if (outPosition != nullptr) {
    *outPosition = static_cast<unsigned short>((static_cast<unsigned int>(packedWord) >> 16u) & 0xFFFFu);
  }
  if (outScrollBarHandle != nullptr) {
    *outScrollBarHandle = static_cast<unsigned int>(scrollBarHandle);
  }
  return outScrollBarHandle;
}

/**
 * Address: 0x00968BA0 (FUN_00968BA0, wxWindow::UnpackCtlColor)
 *
 * What it does:
 * Emits fixed control-id lane `3` and forwards raw message params.
 */
unsigned int* wxWindowMswRuntime::UnpackCtlColor(
  const int wParam,
  const int lParam,
  unsigned short* const outControlId,
  unsigned int* const outWParam,
  unsigned int* const outLParam
)
{
  if (outControlId != nullptr) {
    *outControlId = 3u;
  }
  if (outLParam != nullptr) {
    *outLParam = static_cast<unsigned int>(lParam);
  }
  if (outWParam != nullptr) {
    *outWParam = static_cast<unsigned int>(wParam);
  }
  return outWParam;
}

/**
 * Address: 0x00968C60 (FUN_00968C60, ?MSWDestroyWindow@wxWindow@@UAEXXZ)
 *
 * What it does:
 * Base window runtime lane has no additional destroy-stage behavior.
 */
void wxWindowMswRuntime::MSWDestroyWindow() {}

/**
 * Address: 0x0042B830 (FUN_0042B830)
 * Mangled: ?ContainsHWND@wxWindow@@UBE_NK@Z
 *
 * What it does:
 * Base implementation reports the queried native handle as not contained.
 */
bool wxWindowMswRuntime::ContainsHWND(
  const unsigned long nativeHandle
) const
{
  (void)nativeHandle;
  return false;
}

/**
 * Address: 0x00967930 (FUN_00967930, ?DoReleaseMouse@wxWindow@@MAEXXZ)
 *
 * What it does:
 * Releases the active Win32 mouse-capture lane.
 */
void wxWindowBase::DoReleaseMouse()
{
  ::ReleaseCapture();
}

/**
 * Address: 0x0042B840 (FUN_0042B840)
 * Mangled: ?GetClassInfo@wxWindow@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxWindow runtime RTTI checks.
 */
void* wxWindowMswRuntime::GetClassInfo() const
{
  return gWxWindowClassInfoTable;
}

/**
 * Address: 0x00967EB0 (FUN_00967EB0)
 * Mangled: ?MSWGetStyle@wxWindow@@UBEKJPAK@Z
 *
 * What it does:
 * Converts wx-style lanes into Win32 style/ex-style masks, including auto-3D
 * upgrades for controls and child/non-child parent-background behavior.
 */
unsigned long wxWindowMswRuntime::MSWGetStyle(
  const long style,
  unsigned long* const extendedStyle
) const
{
  unsigned long nativeStyle = (style & kWxWindowStyleClipChildren) != 0 ? kMswStyleClipChildren : kMswStyleBase;

  if ((style & kWxWindowStyleRaisedBorder) != 0) {
    nativeStyle |= kMswStyleRaisedBorder;
  }
  if ((style & kWxWindowStyleSunkenBorder) != 0) {
    nativeStyle |= kMswStyleSunkenBorder;
  }
  if ((style & kWxWindowStyleDoubleBorder) != 0) {
    nativeStyle |= kMswStyleDoubleBorder;
  }

  long styleMaskLane = style & kWxWindowStyleMaskForMsw;
  if (styleMaskLane == 0 && wxTheApp != nullptr && wxTheApp->m_auto3D != 0) {
    if (dynamic_cast<const wxControlRuntime*>(this) != nullptr) {
      const WxWindowBaseRuntimeState* const thisState = FindWxWindowBaseRuntimeState(this);
      wxWindowBase* const parentWindow = thisState != nullptr ? thisState->parentWindow : nullptr;
      if (parentWindow != nullptr && (parentWindow->GetWindowStyleFlag() & kWxWindowStyleNo3D) == 0) {
        styleMaskLane = (style & kWxWindowStyleMaskAuto3DBase) | kWxWindowStyleAuto3D;
      }
    }
  }

  if ((styleMaskLane & kWxWindowStyleStaticEdge) != 0) {
    nativeStyle |= kMswStyleNo3DBit;
  }

  if (extendedStyle == nullptr) {
    return nativeStyle;
  }

  *extendedStyle = 0;
  if ((style & kWxWindowStyleTabTraversal) != 0) {
    *extendedStyle = kMswExStyleTabTraversal;
  }

  if (styleMaskLane == kWxWindowStyleAuto3D) {
    *extendedStyle |= kMswExStyleClientEdge;
    nativeStyle &= ~kMswStyleNo3DBit;
  } else if (
    styleMaskLane == kWxWindowStyleSimpleBorder || styleMaskLane == kWxWindowStyleDoubleBorderLegacy ||
    styleMaskLane == kWxWindowStyleSimpleBorderAlt
  ) {
    *extendedStyle |= kMswExStyleDlgModalFrame;
  }

  if ((style & kWxWindowStyleNoParentBg) != 0 && !IsTopLevel()) {
    *extendedStyle |= kMswExStyleNoParentNotify;
  }

  return nativeStyle;
}

/**
 * Address: 0x0097CCC0 (FUN_0097CCC0)
 * Mangled: ?AdoptAttributesFromHWND@wxWindow@@UAEXXZ
 *
 * What it does:
 * Reads the attached HWND style bits and mirrors horizontal/vertical scroll
 * flags into the wx window-style lane.
 */
void wxWindowMswRuntime::AdoptAttributesFromHWND()
{
  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(this);
  const HWND nativeWindow = reinterpret_cast<HWND>(state.nativeHandle);
  if (nativeWindow == nullptr) {
    return;
  }

  const long nativeStyle = static_cast<long>(::GetWindowLongW(nativeWindow, GWL_STYLE));
  if ((nativeStyle & WS_VSCROLL) != 0) {
    state.windowStyle |= kWxWindowStyleVerticalScroll;
  }
  if ((nativeStyle & WS_HSCROLL) != 0) {
    state.windowStyle |= kWxWindowStyleHorizontalScroll;
  }
}

namespace
{
  template <typename TWindow>
  [[nodiscard]] wxWindowMswRuntime* AllocateWxMswWindowRuntime() noexcept
  {
    return new (std::nothrow) TWindow();
  }

  [[nodiscard]] bool EqualsWindowClassName(
    const wchar_t* const className,
    const wchar_t* const expected
  ) noexcept
  {
    return className != nullptr && expected != nullptr && ::_wcsicmp(className, expected) == 0;
  }

  [[nodiscard]] bool TryParseRichEditMajorVersion(
    const wchar_t* const className,
    std::int32_t* const outMajorVersion
  ) noexcept
  {
    if (className == nullptr || outMajorVersion == nullptr) {
      return false;
    }

    int majorVersion = 0;
    wchar_t suffix = L'\0';
    if (std::swscanf(className, L"RichEdit%d0%c", &majorVersion, &suffix) != 2) {
      return false;
    }

    *outMajorVersion = majorVersion;
    return true;
  }

  [[nodiscard]] wxWindowMswRuntime* CreateButtonRuntimeFromStyle(
    const signed char styleLane
  ) noexcept
  {
    if (styleLane == 5 || styleLane == 6 || styleLane == 3 || styleLane == 2) {
      return AllocateWxMswWindowRuntime<wxCheckBoxRuntime>();
    }

    if (styleLane == 9 || styleLane == 4) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (styleLane >= 0) {
      switch (styleLane) {
      case 11:
      case 0:
      case 1:
      case 7:
        return AllocateWxMswWindowRuntime<wxControlRuntime>();
      default:
        return nullptr;
      }
    }

    return AllocateWxMswWindowRuntime<wxControlRuntime>();
  }

  [[nodiscard]] wxWindowMswRuntime* CreateRuntimeFromClassAndStyle(
    const wchar_t* const className,
    const signed char styleLane
  ) noexcept
  {
    if (EqualsWindowClassName(className, L"BUTTON")) {
      return CreateButtonRuntimeFromStyle(styleLane);
    }

    if (EqualsWindowClassName(className, L"COMBOBOX")) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (EqualsWindowClassName(className, L"EDIT")) {
      return AllocateWxMswWindowRuntime<wxTextCtrlRuntime>();
    }

    if (
      EqualsWindowClassName(className, L"LISTBOX") || EqualsWindowClassName(className, L"SCROLLBAR") ||
      EqualsWindowClassName(className, L"MSCTLS_UPDOWN32") || EqualsWindowClassName(className, L"MSCTLS_TRACKBAR32")
    ) {
      return AllocateWxMswWindowRuntime<wxControlRuntime>();
    }

    if (EqualsWindowClassName(className, L"STATIC")) {
      if (styleLane == 0 || styleLane == 2 || styleLane == 11 || styleLane == 14) {
        return AllocateWxMswWindowRuntime<wxControlRuntime>();
      }
      return nullptr;
    }

    return nullptr;
  }
} // namespace

/**
 * Address: 0x0097D080 (FUN_0097D080)
 * Mangled: ?CreateWindowFromHWND@wxWindow@@UAEPAV1@PAV1@K@Z
 *
 * What it does:
 * Adapts one native Win32 HWND into the closest recovered wx runtime control
 * wrapper and adopts HWND-derived attributes.
 */
void* wxWindowMswRuntime::CreateWindowFromHWND(
  void* const parent,
  const unsigned long nativeHandle
)
{
  const HWND nativeWindow = reinterpret_cast<HWND>(nativeHandle);
  if (nativeWindow == nullptr) {
    return nullptr;
  }

  wchar_t windowClassName[64] = {};
  const int classNameLength = ::GetClassNameW(
    nativeWindow, windowClassName, static_cast<int>(sizeof(windowClassName) / sizeof(windowClassName[0]))
  );
  if (classNameLength <= 0) {
    return nullptr;
  }

  const long windowStyle = static_cast<long>(::GetWindowLongW(nativeWindow, GWL_STYLE));
  const signed char styleLane = static_cast<signed char>(windowStyle & 0xFF);
  const std::int32_t windowId = static_cast<std::uint16_t>(::GetDlgCtrlID(nativeWindow));

  wxWindowMswRuntime* const createdWindow = CreateRuntimeFromClassAndStyle(windowClassName, styleLane);
  if (createdWindow == nullptr) {
    return nullptr;
  }

  wxWindowBase* const parentWindow = static_cast<wxWindowBase*>(parent);
  if (parentWindow != nullptr) {
    parentWindow->AddChild(createdWindow);
  }

  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(createdWindow);
  state.windowStyle = windowStyle;
  state.nativeHandle = nativeHandle;
  state.windowId = windowId;
  state.parentWindow = parentWindow;
  state.eventHandler = createdWindow;

  createdWindow->AdoptAttributesFromHWND();
  createdWindow->SetupColours();
  return createdWindow;
}

/**
 * Address: 0x00969970 (FUN_00969970, wxWindow::HandleCaptureChanged)
 *
 * What it does:
 * Builds one mouse-capture-changed event, resolves the previous capture owner
 * from the native handle lane, and dispatches the event through the active
 * window event-handler lane.
 */
bool wxWindowMswRuntime::HandleCaptureChanged(
  const int nativeHandle
)
{
  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(this);
  wxWindowMswRuntime* const previousCapture = wxFindWinFromHandle(nativeHandle);

  WxMouseCaptureChangedEventRuntime captureEvent(
    state.windowId, EnsureWxEvtMouseCaptureChangedRuntimeType(), previousCapture
  );
  captureEvent.mEventObject = this;

  wxWindowBase* const eventHandler = state.eventHandler != nullptr ? state.eventHandler : this;
  const bool handled = eventHandler->ProcessEvent(&captureEvent);

  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(&captureEvent));
  return handled;
}

/**
 * Address: 0x0096C5F0 (FUN_0096C5F0)
 * Mangled: ?HandleDropFiles@wxWindow@@MAE_NPAUHDROP__@@@Z
 *
 * What it does:
 * Converts one Win32 HDROP payload into a drop-files event and dispatches it
 * through the window event-handler lane.
 */
bool wxWindowMswRuntime::HandleDropFiles(
  void* const hDrop
)
{
  const HDROP dropHandle = reinterpret_cast<HDROP>(hDrop);

  WxDropFilesEventRuntime dropEvent{};
  dropEvent.PopulateFromDropHandle(dropHandle);
  ::DragFinish(dropHandle);

  POINT dropPoint{};
  (void)::DragQueryPoint(dropHandle, &dropPoint);

  dropEvent.mEventObject = this;
  dropEvent.mDropPointX = static_cast<std::int32_t>(dropPoint.x);
  dropEvent.mDropPointY = static_cast<std::int32_t>(dropPoint.y);

  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(this);
  wxWindowBase* const eventHandler = state.eventHandler != nullptr ? state.eventHandler : this;
  return eventHandler->ProcessEvent(&dropEvent);
}

/**
 * Address: 0x00993670 (FUN_00993670)
 * Mangled: ?AdoptAttributesFromHWND@wxTextCtrl@@UAEXXZ
 *
 * What it does:
 * Applies text-control specific style mapping from native EDIT/RichEdit HWND
 * styles into the runtime wx style lane and tracks detected RichEdit major
 * version.
 */
void wxTextCtrlRuntime::AdoptAttributesFromHWND()
{
  wxWindowMswRuntime::AdoptAttributesFromHWND();

  WxWindowBaseRuntimeState& baseState = EnsureWxWindowBaseRuntimeState(this);
  WxTextCtrlRuntimeState& textState = EnsureWxTextCtrlRuntimeState(this);
  const HWND nativeWindow = reinterpret_cast<HWND>(baseState.nativeHandle);
  if (nativeWindow == nullptr) {
    textState.richEditMajorVersion = 0;
    return;
  }

  const long nativeStyle = static_cast<long>(::GetWindowLongW(nativeWindow, GWL_STYLE));

  wchar_t className[64] = {};
  const int classNameLength =
    ::GetClassNameW(nativeWindow, className, static_cast<int>(sizeof(className) / sizeof(className[0])));
  if (classNameLength > 0) {
    if (EqualsWindowClassName(className, L"EDIT")) {
      textState.richEditMajorVersion = 0;
    } else {
      std::int32_t richEditMajorVersion = 0;
      if (TryParseRichEditMajorVersion(className, &richEditMajorVersion)) {
        textState.richEditMajorVersion = richEditMajorVersion;
      } else {
        textState.richEditMajorVersion = 0;
      }
    }
  } else {
    textState.richEditMajorVersion = 0;
  }

  if ((nativeStyle & ES_MULTILINE) != 0) {
    baseState.windowStyle |= kWxTextCtrlStyleMultiline;
  }
  if ((nativeStyle & ES_PASSWORD) != 0) {
    baseState.windowStyle |= kWxTextCtrlStylePassword;
  }
  if ((nativeStyle & ES_READONLY) != 0) {
    baseState.windowStyle |= kWxTextCtrlStyleReadOnly;
  }
  if ((nativeStyle & ES_WANTRETURN) != 0) {
    baseState.windowStyle |= kWxTextCtrlStyleProcessEnter;
  }
  if ((nativeStyle & ES_CENTER) != 0) {
    baseState.windowStyle |= kWxTextCtrlStyleCenter;
  }
  if ((nativeStyle & ES_RIGHT) != 0) {
    baseState.windowStyle |= kWxTextCtrlStyleRight;
  }
}

/**
 * Address: 0x00994510 (FUN_00994510)
 * Mangled: ?OnCtlColor@wxTextCtrl@@UAEKKKIIIJ@Z
 *
 * What it does:
 * Applies text-control foreground/background colours and returns one cached
 * solid brush for ctl-color paint requests.
 */
unsigned long wxTextCtrlRuntime::OnCtlColor(
  const unsigned long hdc,
  const unsigned long hwnd,
  const unsigned int nCtlColor,
  const unsigned int message,
  const unsigned int controlId,
  const long result
)
{
  (void)hwnd;
  (void)nCtlColor;
  (void)message;
  (void)controlId;
  (void)result;

  const WxWindowBaseRuntimeState* const thisState = FindWxWindowBaseRuntimeState(this);
  const WxWindowBaseRuntimeState* parentState = nullptr;
  if (thisState != nullptr && thisState->parentWindow != nullptr) {
    parentState = FindWxWindowBaseRuntimeState(thisState->parentWindow);
  }

  const HDC nativeDc = reinterpret_cast<HDC>(hdc);
  const int backgroundMode = (parentState != nullptr && (parentState->bitfields & 0x2u) != 0u) ? TRANSPARENT : OPAQUE;
  (void)::SetBkMode(nativeDc, backgroundMode);

  wxColourRuntime backgroundColour = GetBackgroundColour();
  const bool useWindowBackgroundColour = thisState == nullptr || (thisState->bitfields & 0x4u) != 0u ||
    (GetWindowStyleFlag() & kWxTextCtrlStyleMultiline) != 0;
  if (!useWindowBackgroundColour) {
    const COLORREF systemFace = ::GetSysColor(COLOR_3DFACE);
    backgroundColour = wxColourRuntime::FromRgb(
      static_cast<std::uint8_t>(GetRValue(systemFace)),
      static_cast<std::uint8_t>(GetGValue(systemFace)),
      static_cast<std::uint8_t>(GetBValue(systemFace))
    );
  }

  const COLORREF backgroundColorRef =
    RGB(backgroundColour.mStorage[0], backgroundColour.mStorage[1], backgroundColour.mStorage[2]);
  (void)::SetBkColor(nativeDc, backgroundColorRef);

  const COLORREF textColorRef = ::GetSysColor(COLOR_WINDOWTEXT);
  (void)::SetTextColor(nativeDc, textColorRef);

  const HBRUSH brush = GetOrCreateCtlColorBrush(backgroundColorRef);
  return static_cast<unsigned long>(reinterpret_cast<std::uintptr_t>(brush));
}

/**
 * Address: 0x004A3830 (FUN_004A3830)
 * Mangled: ?Command@wxControl@@UAEXAAVwxCommandEvent@@@Z
 *
 * What it does:
 * Forwards one command-event dispatch into `ProcessCommand`.
 */
void wxControlRuntime::Command(
  void* const commandEvent
)
{
  ProcessCommand(commandEvent);
}

/**
 * Address: 0x004A3840 (FUN_004A3840)
 * Mangled: ?MSWOnDraw@wxControl@@UAE_NPAPAX@Z
 *
 * What it does:
 * Base implementation reports that no owner-draw handling was performed.
 */
bool wxControlRuntime::MSWOnDraw(
  void** const drawStruct
)
{
  (void)drawStruct;
  return false;
}

/**
 * Address: 0x004A3850 (FUN_004A3850)
 * Mangled: ?MSWOnMeasure@wxControl@@UAE_NPAPAX@Z
 *
 * What it does:
 * Base implementation reports that no owner-measure handling was performed.
 */
bool wxControlRuntime::MSWOnMeasure(
  void** const measureStruct
)
{
  (void)measureStruct;
  return false;
}

/**
 * Address: 0x0042B3E0 (FUN_0042B3E0)
 * Mangled: ?SetTitle@wxWindowBase@@UAEXPBG@Z
 *
 * What it does:
 * Base implementation accepts but ignores title updates.
 */
void wxWindowBase::SetTitle(
  const wxStringRuntime& title
)
{
  (void)title;
}

/**
 * Address: 0x0042B3F0 (FUN_0042B3F0)
 * Mangled: ?GetTitle@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Returns an empty runtime wx string for base windows.
 */
wxStringRuntime wxWindowBase::GetTitle() const
{
  return wxStringRuntime::Borrow(L"");
}

/**
 * Address: 0x0042B420 (FUN_0042B420)
 * Mangled: ?SetLabel@wxWindowBase@@UAEXABVwxString@@@Z
 *
 * What it does:
 * Forwards label updates to `SetTitle`.
 */
void wxWindowBase::SetLabel(
  const wxStringRuntime& label
)
{
  SetTitle(label);
}

/**
 * Address: 0x0042B430 (FUN_0042B430)
 * Mangled: ?GetLabel@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Forwards label reads to `GetTitle`.
 */
wxStringRuntime wxWindowBase::GetLabel() const
{
  return GetTitle();
}

/**
 * Address: 0x0042B450 (FUN_0042B450)
 * Mangled: ?SetName@wxWindowBase@@UAEXABVwxString@@@Z
 *
 * What it does:
 * Stores one runtime window-name value.
 */
void wxWindowBase::SetName(
  const wxStringRuntime& name
)
{
  EnsureWxWindowBaseRuntimeState(this).windowName.assign(name.c_str());
}

/**
 * Address: 0x0042B460 (FUN_0042B460)
 * Mangled: ?GetName@wxWindowBase@@UBE?AVwxString@@XZ
 *
 * What it does:
 * Returns the current runtime window-name value.
 */
wxStringRuntime wxWindowBase::GetName() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return wxStringRuntime::Borrow(state != nullptr ? state->windowName.c_str() : L"");
}

/**
 * Address: 0x00967200 (FUN_00967200)
 * Mangled: ?GetBackgroundColour@wxWindowBase@@QBE?AVwxColour@@XZ
 *
 * What it does:
 * Returns one copy of the window background-colour runtime lane.
 */
wxColourRuntime wxWindowBase::GetBackgroundColour() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->backgroundColour : wxColourRuntime::Null();
}

/**
 * Address: 0x00963540 (FUN_00963540)
 * Mangled: ?GetClientAreaOrigin@wxWindowBase@@UBE?AVwxPoint@@XZ
 *
 * What it does:
 * Returns the default client-area origin lane `(0, 0)`.
 */
wxPoint wxWindowBase::GetClientAreaOrigin() const
{
  return wxPoint{0, 0};
}

/**
 * Address: 0x0042B4F0 (FUN_0042B4F0)
 * Mangled: ?GetMinWidth@wxWindowBase@@UBEHXZ
 */
std::int32_t wxWindowBase::GetMinWidth() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->minWidth : -1;
}

/**
 * Address: 0x0042B500 (FUN_0042B500)
 * Mangled: ?GetMinHeight@wxWindowBase@@UBEHXZ
 */
std::int32_t wxWindowBase::GetMinHeight() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->minHeight : -1;
}

/**
 * Address: 0x0042B510 (FUN_0042B510)
 * Mangled: ?GetMaxSize@wxWindowBase@@UBE?AVwxSize@@XZ
 */
wxSize wxWindowBase::GetMaxSize() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  if (state == nullptr) {
    return wxSize{-1, -1};
  }

  return wxSize{state->maxWidth, state->maxHeight};
}

/**
 * Address: 0x0042B4A0 (FUN_0042B4A0)
 *
 * What it does:
 * Returns client size by forwarding to `DoGetClientSize`.
 */
wxSize wxWindowBase::GetClientSize() const
{
  std::int32_t width = 0;
  std::int32_t height = 0;
  DoGetClientSize(&width, &height);
  return wxSize{width, height};
}

/**
 * Address: 0x0042B4D0 (FUN_0042B4D0)
 *
 * What it does:
 * Returns best size by forwarding to `DoGetBestSize`.
 */
wxSize wxWindowBase::GetBestSize() const
{
  return DoGetBestSize();
}

/**
 * Address: 0x0042B530 (FUN_0042B530)
 * Mangled: ?GetBestVirtualSize@wxWindowBase@@UBE?AVwxSize@@XZ
 */
wxSize wxWindowBase::GetBestVirtualSize() const
{
  std::int32_t clientWidth = 0;
  std::int32_t clientHeight = 0;
  DoGetClientSize(&clientWidth, &clientHeight);

  const wxSize bestSize = DoGetBestSize();
  const std::int32_t width = clientWidth > bestSize.x ? clientWidth : bestSize.x;
  const std::int32_t height = clientHeight > bestSize.y ? clientHeight : bestSize.y;
  return wxSize{width, height};
}

/**
 * Address: 0x00963660 (FUN_00963660)
 * Mangled: ?Show@wxWindowBase@@UAE_N_N@Z
 *
 * What it does:
 * Toggles the base visible-state bit (0x02) and reports whether the bit
 * changed for this call.
 */
bool wxWindowBase::Show(
  const bool show
)
{
  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(this);
  const bool currentlyVisible = (state.bitfields & 0x2u) != 0u;
  if (show == currentlyVisible) {
    return false;
  }

  if (show) {
    state.bitfields = static_cast<std::uint8_t>(state.bitfields | 0x2u);
  } else {
    state.bitfields = static_cast<std::uint8_t>(state.bitfields & ~0x2u);
  }
  return true;
}

/**
 * Address: 0x009636A0 (FUN_009636A0)
 * Mangled: ?Enable@wxWindowBase@@UAE_N_N@Z
 *
 * What it does:
 * Toggles the base enabled-state bit (0x04) and reports whether the bit
 * changed for this call.
 */
bool wxWindowBase::Enable(
  const bool enable
)
{
  WxWindowBaseRuntimeState& state = EnsureWxWindowBaseRuntimeState(this);
  const bool currentlyEnabled = (state.bitfields & 0x4u) != 0u;
  if (enable == currentlyEnabled) {
    return false;
  }

  if (enable) {
    state.bitfields = static_cast<std::uint8_t>(state.bitfields | 0x4u);
  } else {
    state.bitfields = static_cast<std::uint8_t>(state.bitfields & ~0x4u);
  }
  return true;
}

/**
 * Address: 0x0042B5B0 (FUN_0042B5B0)
 * Mangled: ?SetWindowStyleFlag@wxWindowBase@@UAEXJ@Z
 */
void wxWindowBase::SetWindowStyleFlag(
  const long style
)
{
  EnsureWxWindowBaseRuntimeState(this).windowStyle = style;
}

/**
 * Address: 0x0042B5C0 (FUN_0042B5C0)
 * Mangled: ?GetWindowStyleFlag@wxWindowBase@@UBEJXZ
 */
long wxWindowBase::GetWindowStyleFlag() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->windowStyle : 0;
}

/**
 * Address: 0x0042B5F0 (FUN_0042B5F0)
 * Mangled: ?IsRetained@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::IsRetained() const
{
  return ((static_cast<unsigned long>(GetWindowStyleFlag()) >> 17) & 1u) != 0u;
}

/**
 * Address: 0x0042B600 (FUN_0042B600)
 * Mangled: ?SetExtraStyle@wxWindowBase@@UAEXJ@Z
 */
void wxWindowBase::SetExtraStyle(
  const long style
)
{
  EnsureWxWindowBaseRuntimeState(this).extraStyle = style;
}

/**
 * Address: 0x0042B610 (FUN_0042B610)
 * Mangled: ?SetThemeEnabled@wxWindowBase@@UAEX_N@Z
 */
void wxWindowBase::SetThemeEnabled(
  const bool enabled
)
{
  EnsureWxWindowBaseRuntimeState(this).themeEnabled = enabled;
}

/**
 * Address: 0x0042B620 (FUN_0042B620)
 * Mangled: ?GetThemeEnabled@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::GetThemeEnabled() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr && state->themeEnabled;
}

/**
 * Address: 0x0042B630 (FUN_0042B630)
 * Mangled: ?SetFocusFromKbd@wxWindowBase@@UAEXXZ
 */
void wxWindowBase::SetFocusFromKbd()
{
  SetFocus();
}

/**
 * Address: 0x0042B640 (FUN_0042B640)
 * Mangled: ?AcceptsFocus@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::AcceptsFocus() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  if (state == nullptr) {
    return false;
  }

  const std::uint8_t bitfields = state->bitfields;
  return (bitfields & 0x2u) != 0 && (bitfields & 0x4u) != 0;
}

/**
 * Address: 0x0042B660 (FUN_0042B660)
 * Mangled: ?AcceptsFocusFromKeyboard@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::AcceptsFocusFromKeyboard() const
{
  return AcceptsFocus();
}

/**
 * Address: 0x0042B670 (FUN_0042B670)
 * Mangled: ?GetDefaultItem@wxWindowBase@@UBEPAVwxWindow@@XZ
 */
void* wxWindowBase::GetDefaultItem() const
{
  return nullptr;
}

/**
 * Address: 0x0042B680 (FUN_0042B680)
 * Mangled: ?SetDefaultItem@wxWindowBase@@UAEPAVwxWindow@@PAV2@@Z
 */
void* wxWindowBase::SetDefaultItem(
  void* const defaultItem
)
{
  (void)defaultItem;
  return nullptr;
}

/**
 * Address: 0x0042B690 (FUN_0042B690)
 * Mangled: ?SetTmpDefaultItem@wxWindowBase@@UAEXPAVwxWindow@@@Z
 */
void wxWindowBase::SetTmpDefaultItem(
  void* const defaultItem
)
{
  (void)defaultItem;
}

/**
 * Address: 0x0042B6E0 (FUN_0042B6E0)
 * Mangled: ?HasCapture@wxWindowBase@@UBE_NXZ
 */
bool wxWindowBase::HasCapture() const
{
  return this == GetCapture();
}

wxWindowBase* wxWindowBase::GetCapture()
{
  return gCapturedWindow;
}

/**
 * Address: 0x00964CA0 (FUN_00964CA0)
 * Mangled: ?CaptureMouse@wxWindowBase@@QAEXXZ
 *
 * What it does:
 * Releases any previous capture owner, pushes it onto the capture-history
 * stack lane, then requests capture for this window.
 */
void wxWindowBase::CaptureMouse()
{
  wxWindowBase* const previousCapture = GetCapture();
  if (previousCapture != nullptr) {
    previousCapture->DoReleaseMouse();

    auto* const historyNode = new (std::nothrow) WxWindowCaptureHistoryNode{};
    if (historyNode != nullptr) {
      historyNode->window = previousCapture;
      historyNode->next = gWindowCaptureHistoryHead;
      gWindowCaptureHistoryHead = historyNode;
    }
  }

  DoCaptureMouse();
}

/**
 * Address: 0x0042B700 (FUN_0042B700)
 */
void wxWindowBase::Update() {}

/**
 * Address: 0x0042B710 (FUN_0042B710)
 */
void wxWindowBase::Freeze() {}

/**
 * Address: 0x0042B720 (FUN_0042B720)
 */
void wxWindowBase::Thaw() {}

/**
 * Address: 0x0042B730 (FUN_0042B730)
 * Mangled: ?PrepareDC@wxWindowBase@@UAEXAAVwxDC@@@Z
 */
void wxWindowBase::PrepareDC(
  void* const deviceContext
)
{
  (void)deviceContext;
}

/**
 * Address: 0x0042B740 (FUN_0042B740)
 */
bool wxWindowBase::ScrollLines(
  const std::int32_t lines
)
{
  (void)lines;
  return false;
}

/**
 * Address: 0x0042B750 (FUN_0042B750)
 */
bool wxWindowBase::ScrollPages(
  const std::int32_t pages
)
{
  (void)pages;
  return false;
}

void wxWindowBase::SetDropTarget(
  void* const dropTarget
)
{
  EnsureWxWindowBaseRuntimeState(this).dropTarget = dropTarget;
}

/**
 * Address: 0x0042B760 (FUN_0042B760)
 * Mangled: ?GetDropTarget@wxWindowBase@@UBEPAVwxDropTarget@@XZ
 */
void* wxWindowBase::GetDropTarget() const
{
  const WxWindowBaseRuntimeState* const state = FindWxWindowBaseRuntimeState(this);
  return state != nullptr ? state->dropTarget : nullptr;
}

/**
 * Address: 0x00992230 (FUN_00992230, ?Pending@wxApp@@UAE_NXZ)
 *
 * What it does:
 * Reports whether at least one Win32 message is pending without removing it.
 */
bool wxApp::Pending()
{
  return ::PeekMessageW(&gCurrentMessage, nullptr, 0u, 0u, 0u) != FALSE;
}

/**
 * Address: 0x00992250 (FUN_00992250, ?Dispatch@wxApp@@UAEXXZ)
 *
 * What it does:
 * Dispatches one queued app-loop message through the recovered wx runtime lane.
 */
void wxApp::Dispatch()
{
  (void)DoMessage();
}

/**
 * Address: 0x009AA860 (FUN_009AA860, ?OnExit@wxAppBase@@UAEHXZ)
 *
 * What it does:
 * Base wx app shutdown hook. The recovered FA lane returns success (`0`)
 * after higher-level teardown paths complete.
 */
int wxApp::OnExit()
{
  return 0;
}

/**
 * Address: 0x00992190 (FUN_00992190, ?ProcessIdle@wxApp@@UAE_NXZ)
 *
 * What it does:
 * Builds one idle event, dispatches it through the app event-handler lane,
 * and returns the idle-event `request more` flag.
 */
bool wxApp::ProcessIdle()
{
  WxIdleEventRuntime idleEvent{};
  idleEvent.mEventObject = this;

  (void)ProcessEvent(&idleEvent);
  const bool requestMore = idleEvent.mRequestMore;
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(&idleEvent));
  return requestMore;
}

/**
 * Address: 0x00993100 (FUN_00993100)
 * Mangled: ?DoMessage@wxApp@@UAE_NXZ
 *
 * What it does:
 * Reads one Win32 message and dispatches it immediately on the GUI-owner
 * thread; background-thread messages are copied into one deferred queue lane.
 */
bool wxApp::DoMessage()
{
  const int getMessageResult = ::GetMessageW(&gCurrentMessage, nullptr, 0, 0);
  if (getMessageResult == 0) {
    m_keepGoing = 0;
    return false;
  }

  if (getMessageResult == -1) {
    return true;
  }

  EnsureDeferredThreadMessageQueueInitialized();

  if (IsGuiOwnedByMainThread()) {
    DispatchDeferredThreadMessages(*this);
    ProcessMessage(reinterpret_cast<void**>(&gCurrentMessage));
  } else {
    gIsDispatchingDeferredMessages = false;
    if (!ShouldSuppressDeferredCommandMessages() || gCurrentMessage.message != kWin32CommandMessageId) {
      QueueDeferredThreadMessage(gCurrentMessage, 1u);
    }
  }

  return true;
}

msvc8::vector<moho::ManagedWindowSlot> moho::managedWindows{};
msvc8::vector<moho::ManagedWindowSlot> moho::managedFrames{};
wxWindowBase* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;

moho::wxDCRuntime::wxDCRuntime(
  wxWindowBase* const ownerWindow
) noexcept
  : mOwnerWindow(ownerWindow)
{}

void moho::wxDCRuntime::SetBrush(
  const void* const brushToken
) noexcept
{
  mActiveBrush = brushToken;
}

void moho::wxDCRuntime::DoGetSize(
  std::int32_t* const outWidth,
  std::int32_t* const outHeight
) const noexcept
{
  if (mOwnerWindow != nullptr) {
    mOwnerWindow->DoGetSize(outWidth, outHeight);
    return;
  }

  if (outWidth != nullptr) {
    *outWidth = 0;
  }
  if (outHeight != nullptr) {
    *outHeight = 0;
  }
}

void moho::wxDCRuntime::DoDrawRectangle(
  const std::int32_t x,
  const std::int32_t y,
  const std::int32_t width,
  const std::int32_t height
) noexcept
{
  (void)x;
  (void)y;
  (void)width;
  (void)height;
  (void)mActiveBrush;
}

moho::wxPaintDCRuntime::wxPaintDCRuntime(
  wxWindowBase* const ownerWindow
) noexcept
  : wxDCRuntime(ownerWindow)
{}

moho::wxPaintDCRuntime::~wxPaintDCRuntime() = default;

bool moho::WX_EnsureSplashPngHandler()
{
  if (gSplashPngHandlerInitialized) {
    return true;
  }

  // Source-only runtime tracks registration state without importing wx handlers.
  gSplashPngHandlerInitialized = true;
  return true;
}

moho::SplashScreenRuntime* moho::WX_CreateSplashScreen(
  const char* const filename,
  const wxSize& size
)
{
  if (filename == nullptr || filename[0] == '\0') {
    return nullptr;
  }

  std::error_code pathError;
  std::filesystem::path splashPath(filename);
  if (!splashPath.is_absolute()) {
    splashPath = std::filesystem::absolute(splashPath, pathError);
    if (pathError) {
      return nullptr;
    }
  }

  if (!std::filesystem::exists(splashPath, pathError) || pathError) {
    return nullptr;
  }

  msvc8::string splashPathText;
  splashPathText.assign_owned(splashPath.generic_string());
  return new (std::nothrow) SplashScreenRuntimeImpl(splashPathText, size);
}

void* moho::WD3DViewport::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x00430980 (FUN_00430980)
 * Mangled:
 * ??0WD3DViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxPoint@@ABVwxSize@@@Z
 *
 * What it does:
 * Converts the startup title lane to wide text for wx window creation flow,
 * binds parent ownership, and clears retained D3D device reference storage.
 */
moho::WD3DViewport::WD3DViewport(
  wxWindowBase* const parentWindow,
  const char* const title,
  const wxPoint& position,
  const wxSize& size
)
{
  (void)position;
  (void)size;

  const std::wstring wideTitle = gpg::STR_Utf8ToWide(title != nullptr ? title : "");
  (void)wideTitle;

  std::memset(mUnknown04To0C, 0, sizeof(mUnknown04To0C));
  mRenderState0C = -1;
  std::memset(mUnknown10To1D, 0, sizeof(mUnknown10To1D));
  mEnabled = 0;
  std::memset(mUnknown1ETo2B, 0, sizeof(mUnknown1ETo2B));
  m_parent = parentWindow;
  mD3DDevice = nullptr;
}

/**
 * Address: 0x0042BA90 (FUN_0042BA90)
 * Mangled: ??1WD3DViewport@Moho@@UAE@XZ
 *
 * What it does:
 * Releases one held D3D-device reference before base window teardown.
 */
moho::WD3DViewport::~WD3DViewport()
{
  ReleaseD3DDeviceRef(mD3DDevice);
  mD3DDevice = nullptr;
}

/**
 * Address: 0x0042BAF0 (FUN_0042BAF0)
 */
void moho::WD3DViewport::D3DWindowOnDeviceInit() {}

/**
 * Address: 0x0042BB00 (FUN_0042BB00)
 */
void moho::WD3DViewport::D3DWindowOnDeviceRender() {}

/**
 * Address: 0x0042BB10 (FUN_0042BB10)
 */
void moho::WD3DViewport::D3DWindowOnDeviceExit() {}

/**
 * Address: 0x0042BB20 (FUN_0042BB20)
 */
void moho::WD3DViewport::RenderPreviewImage() {}

/**
 * Address: 0x0042BB30 (FUN_0042BB30)
 */
moho::WPreviewImageRuntime moho::WD3DViewport::GetPreviewImage() const
{
  return {};
}

/**
 * Address: 0x0042BB50 (FUN_0042BB50)
 */
void* moho::WD3DViewport::GetPrimBatcher() const
{
  return nullptr;
}

/**
 * Address: 0x00430970 (FUN_00430970)
 * Mangled: ?GetEventTable@WD3DViewport@Moho@@MBEPBUwxEventTable@@XZ
 *
 * What it does:
 * Returns the static event-table lane for this viewport runtime type.
 */
const void* moho::WD3DViewport::GetEventTable() const
{
  return sm_eventTable;
}

namespace
{
  constexpr std::uintptr_t kWxBlackBrushToken = 1u;
  constexpr std::uintptr_t kWxNullBrushToken = 0u;
  constexpr std::uint16_t kClientHitTestCode = 1u;

  void DrawBackgroundFill(
    moho::wxDCRuntime& deviceContext
  )
  {
    std::int32_t width = 0;
    std::int32_t height = 0;

    deviceContext.SetBrush(reinterpret_cast<const void*>(kWxBlackBrushToken));
    deviceContext.DoGetSize(&width, &height);
    deviceContext.DoDrawRectangle(0, 0, width, height);
    deviceContext.SetBrush(reinterpret_cast<const void*>(kWxNullBrushToken));
  }

  struct [[maybe_unused]] WD3DViewportPaintCallbackFrame
  {
    std::uint8_t mUnknown00To1F[0x20]{};
    moho::wxDCRuntime* mDeviceContext = nullptr;
  };

  static_assert(
    offsetof(WD3DViewportPaintCallbackFrame, mDeviceContext) == 0x20,
    "WD3DViewportPaintCallbackFrame::mDeviceContext offset must be 0x20"
  );

  /**
   * Address: 0x00430B70 (FUN_00430B70)
   *
   * What it does:
   * Draws viewport background into the supplied paint DC when D3D device is
   * missing or still in background-fallback mode.
   */
  [[maybe_unused]] void WD3DViewportPaintBackgroundFallback(
    WD3DViewportPaintCallbackFrame* const callbackFrame
  )
  {
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (callbackFrame == nullptr || callbackFrame->mDeviceContext == nullptr) {
      return;
    }

    if (device == nullptr || device->ShouldDrawViewportBackground()) {
      DrawBackgroundFill(*callbackFrame->mDeviceContext);
    }
  }
} // namespace

/**
 * Address: 0x00430A60 (FUN_00430A60)
 * Mangled: ?DrawBackgroundImage@WD3DViewport@Moho@@AAEXAAVwxDC@@@Z
 *
 * What it does:
 * Fills the viewport paint DC with a solid black rectangle.
 */
void moho::WD3DViewport::DrawBackgroundImage(
  wxDCRuntime& deviceContext
)
{
  DrawBackgroundFill(deviceContext);
}

/**
 * Address: 0x00430AC0 (FUN_00430AC0)
 * Mangled: ?OnPaint@WD3DViewport@Moho@@QAEXAAVwxPaintEvent@@@Z
 *
 * What it does:
 * Builds one paint DC, then renders through active D3D device when ready or
 * draws fallback background.
 */
void moho::WD3DViewport::OnPaint(
  wxPaintEventRuntime& paintEvent
)
{
  (void)paintEvent;
  wxPaintDCRuntime paintDc(this);

  CD3DDevice* const device = D3D_GetDevice();
  if (gpg::gal::Device::IsReady() && device != nullptr) {
    ReleaseD3DDeviceRef(mD3DDevice);
    mD3DDevice = nullptr;
    device->Paint();
    return;
  }

  DrawBackgroundImage(paintDc);
}

/**
 * Address: 0x00430B90 (FUN_00430B90)
 * Mangled: ?MSWWindowProc@WD3DViewport@Moho@@UAEJIIJ@Z
 *
 * What it does:
 * Handles cursor ownership handoff between wx and D3D, then delegates
 * unhandled messages to base window dispatch.
 */
long moho::WD3DViewport::MSWWindowProc(
  const unsigned int message,
  const unsigned int wParam,
  const long lParam
)
{
  CD3DDevice* const device = D3D_GetDevice();
  if (device != nullptr) {
    const bool setCursorMessage = message == WM_SETCURSOR;
    const bool clientHit = static_cast<std::uint16_t>(lParam & 0xFFFF) == kClientHitTestCode;

    if (d3d_WindowsCursor) {
      if (setCursorMessage && clientHit && device->IsCursorPixelSourceReady()) {
        gpg::gal::Device::InitCursor();
        (void)device->ShowCursor(device->IsCursorShowing());
        return 1;
      }
    } else if (setCursorMessage && clientHit && (device->IsCursorPixelSourceReady() || !device->IsCursorShowing())) {
      ::SetCursor(nullptr);
      gpg::gal::Device::InitCursor();
      (void)device->ShowCursor(device->IsCursorShowing());
      return 1;
    }
  }

  return WRenViewport::MSWWindowProc(message, wParam, lParam);
}

/**
 * Address: 0x0042BB60 (FUN_0042BB60)
 *
 * What it does:
 * Deleting-dtor thunk lane for `WD3DViewport`.
 */
static moho::WD3DViewport* DeleteWD3DViewportThunk(
  moho::WD3DViewport* const viewport,
  const std::uint8_t deleteFlags
)
{
  if (viewport == nullptr) {
    return nullptr;
  }

  viewport->~WD3DViewport();
  if ((deleteFlags & 1u) != 0u) {
    operator delete(viewport);
  }
  return viewport;
}

namespace
{
  constexpr std::size_t kMaxCommittedLogLines = 10000;
  constexpr std::uint32_t kCustomFilterCategoryBit = 1u << 4;
  constexpr std::uint32_t kWarningCategoryValue = 2u;
  constexpr std::uint32_t kErrorCategoryValue = 3u;
  constexpr std::size_t kReplayIndentWidth = 4u;
  constexpr const char* kLogCategoryPreferenceKeys[] = {
    "Options.Log.Debug",
    "Options.Log.Info",
    "Options.Log.Warn",
    "Options.Log.Error",
    "Options.Log.Custom",
  };
  constexpr bool kLogCategoryPreferenceDefaults[] = {
    false,
    true,
    true,
    true,
    true,
  };
  constexpr const char* kLogFilterPreferenceKey = "Options.Log.Filter";
  constexpr const char* kLogFilterPreferenceDefault = "*DEBUG:";
  constexpr const char* kLogWindowXPreferenceKey = "Windows.Log.x";
  constexpr const char* kLogWindowYPreferenceKey = "Windows.Log.y";
  constexpr const char* kLogWindowWidthPreferenceKey = "Windows.Log.width";
  constexpr const char* kLogWindowHeightPreferenceKey = "Windows.Log.height";
  constexpr std::int32_t kLogWindowGeometryFallback = -1;
  constexpr std::int32_t kLogWindowSetSizeFlags = 3;

  [[nodiscard]] wxTextAttrRuntime BuildTextStyleFromRgb(
    const std::uint8_t red,
    const std::uint8_t green,
    const std::uint8_t blue
  ) noexcept
  {
    return wxTextAttrRuntime(
      wxColourRuntime::FromRgb(red, green, blue), wxColourRuntime::Null(), wxFontRuntime::Null()
    );
  }

  [[nodiscard]] wxTextAttrRuntime DefaultTextStyleForCategory(
    const std::uint32_t category
  ) noexcept
  {
    switch (category) {
    case 0u:
      return BuildTextStyleFromRgb(0x80, 0x80, 0x80);
    case kWarningCategoryValue:
      return BuildTextStyleFromRgb(0xF7, 0xA1, 0x00);
    case kErrorCategoryValue:
      return BuildTextStyleFromRgb(0xFF, 0x00, 0x00);
    default:
      return BuildTextStyleFromRgb(0x00, 0x00, 0x00);
    }
  }
} // namespace

wxStreamBase::wxStreamBase() = default;

/**
 * Address: 0x009DCF40 (FUN_009DCF40)
 * Mangled: ??0wxInputStream@@QAE@@Z
 *
 * What it does:
 * Initializes pushback-lane counters to zero and binds input-stream base
 * runtime state.
 */
wxInputStream::wxInputStream()
  : wxStreamBase()
  , m_wback(0)
  , m_wbackcur(0)
  , m_wbacksize(0)
{}

/**
 * Address: 0x009DDDE0 (FUN_009DDDE0, wxFileExists)
 *
 * What it does:
 * Returns true when the provided wx-string path resolves to an existing file
 * path that is not a directory.
 */
bool wxFileExists(
  const wxStringRuntime* const fileName
)
{
  if (fileName == nullptr || fileName->m_pchData == nullptr) {
    return false;
  }

  const DWORD attributes = ::GetFileAttributesW(fileName->m_pchData);
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

/**
 * Address: 0x00A12870 (FUN_00A12870)
 * Mangled: ??0wxFile@@QAE@PBGW4OpenMode@0@@Z
 *
 * What it does:
 * Initializes one file lane and opens the provided wide path with read mode.
 */
wxFile::wxFile(
  const wchar_t* const fileName,
  const OpenMode mode
)
  : m_fd(-1)
  , m_error(0)
{
  (void)Open(fileName, mode, 438);
}

wxFile::~wxFile()
{
  if (m_fd != -1) {
    (void)_close(m_fd);
    m_fd = -1;
  }
}

/**
 * Address: 0x00A11F50 (FUN_00A11F50)
 * Mangled: ?Exists@wxFile@@SA_NPB_W@Z
 *
 * What it does:
 * Builds one temporary wx-string from a wide path and probes whether it maps
 * to an existing non-directory file.
 */
bool wxFile::Exists(
  const wchar_t* const fileName
)
{
  wxStringRuntime path = AllocateOwnedWxString(fileName != nullptr ? std::wstring(fileName) : std::wstring());
  const bool exists = wxFileExists(&path);
  ReleaseOwnedWxString(path);
  return exists;
}

bool wxFile::Open(
  const wchar_t* const fileName,
  const OpenMode mode,
  const std::int32_t permissions
)
{
  (void)mode;
  if (m_fd != -1) {
    (void)_close(m_fd);
    m_fd = -1;
  }

  if (fileName == nullptr || *fileName == L'\0') {
    m_error = 1;
    return false;
  }

  m_fd = _wopen(fileName, _O_BINARY | _O_RDONLY, permissions);
  m_error = m_fd == -1 ? 1 : 0;
  return m_fd != -1;
}

/**
 * Address: 0x009DBAF0 (FUN_009DBAF0)
 * Mangled: ??0wxFileInputStream@@QAE@@Z
 *
 * What it does:
 * Builds one file-backed input stream from a path string by allocating a
 * `wxFile` lane and marking it as stream-owned for destruction.
 */
wxFileInputStream::wxFileInputStream(
  const wxStringRuntime& fileName
)
  : wxInputStream()
{
  if (wxFile* const file = new (std::nothrow) wxFile(fileName.c_str(), wxFile::OpenRead); file != nullptr) {
    m_file = file;
  } else {
    m_file = nullptr;
  }
  m_file_destroy = 1;
}

wxFileInputStream::~wxFileInputStream()
{
  if (m_file_destroy != 0u) {
    delete m_file;
  }
  m_file = nullptr;
  m_file_destroy = 0;
}

void wxFileName::SplitPath(
  const wxStringRuntime& input,
  wxStringRuntime* const volume,
  wxStringRuntime* const path,
  wxStringRuntime* const name,
  wxStringRuntime* const ext,
  const wchar_t* const formatHint
)
{
  (void)formatHint;

  std::wstring volumeText;
  std::wstring pathText;
  std::wstring nameText;
  std::wstring extText;

  try {
    const std::filesystem::path inputPath(input.c_str());
    volumeText = inputPath.root_name().wstring();

    pathText = inputPath.parent_path().wstring();
    const std::wstring rootPathText = inputPath.root_path().wstring();
    if (!rootPathText.empty() && pathText.rfind(rootPathText, 0) == 0) {
      pathText.erase(0, rootPathText.size());
    }

    nameText = inputPath.stem().wstring();
    extText = inputPath.extension().wstring();
    if (!extText.empty() && extText.front() == L'.') {
      extText.erase(0, 1);
    }
  } catch (const std::exception&) {
    volumeText.clear();
    pathText.clear();
    nameText.clear();
    extText.clear();
  }

  AssignOwnedWxString(volume, volumeText);
  AssignOwnedWxString(path, pathText);
  AssignOwnedWxString(name, nameText);
  AssignOwnedWxString(ext, extText);
}

/**
 * Address: 0x009F46E0 (FUN_009F46E0)
 * Mangled: ?wxGetVolumeString@@YA?AVwxString@@ABV1@W4wxPathFormat@@@Z
 *
 * What it does:
 * Builds one normalized volume-prefix text lane used by `SplitPath_0`.
 */
wxStringRuntime wxGetVolumeString(
  const wxStringRuntime& volume,
  const wchar_t* const formatHint
)
{
  const std::wstring volumeText(volume.c_str());
  if (volumeText.empty()) {
    return AllocateOwnedWxString(L"");
  }

  const std::uintptr_t rawFormatHint = reinterpret_cast<std::uintptr_t>(formatHint);
  std::int32_t pathFormat = 4;
  if (rawFormatHint <= 0x10u) {
    pathFormat = rawFormatHint == 0u ? 4 : static_cast<std::int32_t>(rawFormatHint);
  }

  std::wstring outputText;
  if (pathFormat == 3) {
    if (volumeText.size() > 1u) {
      outputText = L"\\\\";
      outputText += volumeText;
    } else {
      outputText = volumeText;
      outputText.push_back(L':');
    }
  } else if (pathFormat == 4) {
    outputText = volumeText;
    outputText.push_back(L':');
  }

  return AllocateOwnedWxString(outputText);
}

/**
 * Address: 0x009F5820 (FUN_009F5820)
 * Mangled: ?SplitPath_0@wxFileName@@SAXABVwxString@@PAV2@00PA_W@Z
 *
 * What it does:
 * Splits path components, then prepends the computed volume-prefix lane onto
 * the output path lane when requested.
 */
void wxFileName::SplitPath_0(
  const wxStringRuntime& input,
  wxStringRuntime* const path,
  wxStringRuntime* const name,
  wxStringRuntime* const ext,
  const wchar_t* const formatHint
)
{
  wxStringRuntime volume = wxStringRuntime::Borrow(L"");
  SplitPath(input, &volume, path, name, ext, formatHint);

  if (path != nullptr) {
    wxStringRuntime volumePrefix = wxGetVolumeString(volume, formatHint);
    PrependOwnedWxString(path, volumePrefix);
    ReleaseOwnedWxString(volumePrefix);
  }

  ReleaseOwnedWxString(volume);
}

wxDCBase::wxDCBase() = default;

/**
 * Address: 0x009CA490 (FUN_009CA490)
 * Mangled: ??0wxDC@@QAE@@Z
 *
 * What it does:
 * Initializes one device-context lane with cleared selected object and native
 * handle ownership state.
 */
wxDC::wxDC()
  : wxDCBase()
{
  m_selectedBitmap = nullptr;
  m_bOwnsDC &= static_cast<std::uint8_t>(~1u);
  m_canvas = nullptr;
  m_oldBitmap = nullptr;
  m_oldPen = nullptr;
  m_oldBrush = nullptr;
  m_oldFont = nullptr;
  m_oldPalette = nullptr;
  m_hDC = nullptr;
}

/**
 * Address: 0x009D45B0 (FUN_009D45B0)
 * Mangled: ??0wxMemoryDC@@QAE@@Z
 *
 * What it does:
 * Constructs one memory DC, allocates a compatible native DC handle, then
 * initializes default pen/brush/background mode lanes.
 */
wxMemoryDC::wxMemoryDC()
  : wxDC()
{
  (void)CreateCompatible(nullptr);
  Init();
}

/**
 * Address: 0x009D4430 (FUN_009D4430)
 * Mangled: ?CreateCompatible@wxMemoryDC@@QAE_NPAVwxDC@@@Z
 */
bool wxMemoryDC::CreateCompatible(
  wxDC* const sourceDc
)
{
  HDC sourceHandle = nullptr;
  if (sourceDc != nullptr) {
    sourceHandle = reinterpret_cast<HDC>(sourceDc->GetNativeHandle());
  }

  HDC const compatibleDc = ::CreateCompatibleDC(sourceHandle);
  m_bOwnsDC |= 1u;
  m_hDC = compatibleDc;
  m_flags =
    static_cast<std::uint8_t>((m_flags & static_cast<std::uint8_t>(~0x2u)) | (compatibleDc != nullptr ? 0x2u : 0u));
  return (m_flags & 0x2u) != 0u;
}

/**
 * Address: 0x009D43F0 (FUN_009D43F0)
 * Mangled: ?Init@wxMemoryDC@@AAEXXZ
 */
void wxMemoryDC::Init()
{
  if ((m_flags & 0x2u) == 0u) {
    return;
  }

  SetBrush(::GetStockObject(WHITE_BRUSH));
  SetPen(::GetStockObject(BLACK_PEN));
  (void)::SetBkMode(reinterpret_cast<HDC>(m_hDC), 1);
}

void wxMemoryDC::SetBrush(
  void* const brushToken
)
{
  m_oldBrush = brushToken;
}

void wxMemoryDC::SetPen(
  void* const penToken
)
{
  m_oldPen = penToken;
}

[[nodiscard]] const wchar_t* wxStringRuntime::c_str() const noexcept
{
  return m_pchData != nullptr ? m_pchData : L"";
}

msvc8::string wxStringRuntime::ToUtf8() const
{
  return gpg::STR_WideToUtf8(c_str());
}

msvc8::string wxStringRuntime::ToUtf8Lower() const
{
  const msvc8::string value = ToUtf8();
  return gpg::STR_ToLower(value.c_str());
}

/**
 * Address: 0x0095FFD0 (FUN_0095FFD0, func_wstrFind)
 *
 * What it does:
 * Selects first-or-last wide-char search over this string lane and returns
 * a zero-based character index, or `-1` when no match exists.
 */
std::int32_t wxStringRuntime::FindCharacterIndex(
  const wchar_t needle,
  const bool findFromRight
) const noexcept
{
  wchar_t* const text = m_pchData;
  wchar_t* const match =
    findFromRight ? const_cast<wchar_t*>(std::wcsrchr(text, needle)) : const_cast<wchar_t*>(std::wcschr(text, needle));
  if (match == nullptr) {
    return -1;
  }

  return static_cast<std::int32_t>(match - text);
}

/**
 * Address: 0x009610B0 (FUN_009610B0, wxString::Empty)
 *
 * What it does:
 * Truncates one wx string to `newLength` when shortening is requested and the
 * target payload is writable after copy-before-write checks.
 */
wxStringRuntime* wxStringRuntime::Empty(
  const std::uint32_t newLength
)
{
  if (m_pchData == nullptr || !IsOwnedWxString(*this)) {
    return this;
  }

  auto* const header = reinterpret_cast<WxOwnedStringHeader*>(reinterpret_cast<std::int32_t*>(m_pchData) - 3);
  const auto currentLength = static_cast<std::uint32_t>(header->length);
  if (newLength < currentLength && EnsureUniqueOwnedWxStringBuffer(this)) {
    m_pchData[newLength] = L'\0';

    auto* const writableHeader = reinterpret_cast<WxOwnedStringHeader*>(reinterpret_cast<std::int32_t*>(m_pchData) - 3);
    writableHeader->length = static_cast<std::int32_t>(newLength);
  }

  return this;
}

wxStringRuntime wxStringRuntime::Borrow(
  const wchar_t* const text
) noexcept
{
  wxStringRuntime runtime{};
  runtime.m_pchData = const_cast<wchar_t*>(text != nullptr ? text : L"");
  return runtime;
}

/**
 * Address: 0x0042B870 (FUN_0042B870)
 * Mangled: ??0wxImageHandler@@QAE@@Z
 *
 * What it does:
 * Initializes name/extension/mime string lanes and sets type to invalid.
 */
wxImageHandlerRuntime::wxImageHandlerRuntime()
{
  mRefData = nullptr;
  mName = wxStringRuntime::Borrow(L"");
  mExtension = wxStringRuntime::Borrow(L"");
  mMime = wxStringRuntime::Borrow(L"");
  mType = 0;
}

void wxImageHandlerRuntime::SetDescriptor(
  const wchar_t* const name,
  const wchar_t* const extension,
  const wchar_t* const mimeType,
  const std::int32_t bitmapType
) noexcept
{
  mName = wxStringRuntime::Borrow(name != nullptr ? name : L"");
  mExtension = wxStringRuntime::Borrow(extension != nullptr ? extension : L"");
  mMime = wxStringRuntime::Borrow(mimeType != nullptr ? mimeType : L"");
  mType = bitmapType;
}

/**
 * Address: 0x0042B8F0 (FUN_0042B8F0)
 * Mangled: ?GetClassInfo@wxImageHandler@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxImageHandler runtime RTTI checks.
 */
void* wxImageHandlerRuntime::GetClassInfo() const
{
  return gWxImageHandlerClassInfoTable;
}

void wxImageHandlerRuntime::ReleaseSharedWxString(
  wxStringRuntime& value
) noexcept
{
  // Runtime wrappers keep wxString lanes as borrowed views; dropping one lane
  // is represented by clearing the pointer.
  value.m_pchData = nullptr;
}

/**
 * Address: 0x0042B920 (FUN_0042B920)
 *
 * What it does:
 * Releases runtime string lanes and clears shared ref-data ownership.
 */
wxImageHandlerRuntime::~wxImageHandlerRuntime()
{
  ReleaseSharedWxString(mMime);
  ReleaseSharedWxString(mExtension);
  ReleaseSharedWxString(mName);
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
}

/**
 * Address: 0x0042B9E0 (FUN_0042B9E0)
 * Mangled: ??0wxPNGHandler@@QAE@XZ
 *
 * What it does:
 * Initializes the PNG handler descriptor (name, extension, mime, bitmap type).
 */
wxPngHandlerRuntime::wxPngHandlerRuntime()
{
  // wxBitmapType::wxBITMAP_TYPE_PNG in this runtime lane.
  constexpr std::int32_t kBitmapTypePng = 15;
  SetDescriptor(L"PNG file", L"png", L"image/png", kBitmapTypePng);
}

/**
 * Address: 0x0042BA50 (FUN_0042BA50)
 * Mangled: ?GetClassInfo@wxPNGHandler@@UBEPAVwxClassInfo@@XZ
 *
 * What it does:
 * Returns the static class-info lane for wxPNGHandler runtime RTTI checks.
 */
void* wxPngHandlerRuntime::GetClassInfo() const
{
  return gWxPngHandlerClassInfoTable;
}

/**
 * Address: 0x0042BA60 (FUN_0042BA60)
 *
 * What it does:
 * Deleting-dtor thunk lane for `wxPNGHandler`; no extra teardown beyond base.
 */
wxPngHandlerRuntime::~wxPngHandlerRuntime() = default;

wxImageRuntime::~wxImageRuntime()
{
  ReleaseRefData();
}

void wxImageRuntime::ReleaseRefData() noexcept
{
  auto* const refData = reinterpret_cast<WxImageRefDataRuntime*>(mRefData);
  if (refData == nullptr) {
    return;
  }

  --refData->mRefCount;
  if (refData->mRefCount == 0) {
    delete refData;
  }

  mRefData = nullptr;
}

/**
 * Address: 0x00970600 (FUN_00970600)
 * Mangled: ?Create@wxImage@@QAEXHH@Z
 *
 * What it does:
 * Drops previous shared image ref-data, allocates one fresh image ref-data
 * object, then allocates/clears 24-bit RGB storage for `width*height`.
 */
void wxImageRuntime::Create(
  const std::int32_t width,
  const std::int32_t height
)
{
  ReleaseRefData();

  auto* const refData = new (std::nothrow) WxImageRefDataRuntime();
  mRefData = refData;
  if (refData == nullptr) {
    return;
  }

  const std::uint32_t wrappedPixelCount = static_cast<std::uint32_t>(width) * static_cast<std::uint32_t>(height);
  const std::int32_t pixelByteCountSigned = static_cast<std::int32_t>(wrappedPixelCount * 3u);
  const std::size_t pixelByteCount = static_cast<std::size_t>(static_cast<std::uint32_t>(pixelByteCountSigned));

  refData->mPixelBytes = static_cast<std::uint8_t*>(std::malloc(pixelByteCount));
  if (refData->mPixelBytes == nullptr) {
    ReleaseRefData();
    return;
  }

  if (pixelByteCountSigned > 0) {
    std::memset(refData->mPixelBytes, 0, static_cast<std::size_t>(pixelByteCountSigned));
  }

  refData->mWidth = width;
  refData->mHeight = height;
  refData->mMaskAndFlags[4] = 1;
}

wxColourRuntime wxColourRuntime::FromRgb(
  const std::uint8_t red,
  const std::uint8_t green,
  const std::uint8_t blue
) noexcept
{
  wxColourRuntime color{};
  color.mStorage[0] = red;
  color.mStorage[1] = green;
  color.mStorage[2] = blue;
  color.mStorage[3] = 0xFF;
  return color;
}

const wxColourRuntime& wxColourRuntime::Null() noexcept
{
  static const wxColourRuntime kNullColour{};
  return kNullColour;
}

const wxFontRuntime& wxFontRuntime::Null() noexcept
{
  static const wxFontRuntime kNullFont{};
  return kNullFont;
}

/**
 * Address: 0x004F36A0 (FUN_004F36A0)
 *
 * What it does:
 * Initializes one text-style payload from explicit foreground/background/font
 * runtime lanes.
 */
wxTextAttrRuntime::wxTextAttrRuntime(
  const wxColourRuntime& foreground,
  const wxColourRuntime& background,
  const wxFontRuntime& font
)
  : mForegroundColour(foreground)
  , mBackgroundColour(background)
  , mFont(font)
{}

/**
 * Address: 0x004F63B0 (FUN_004F63B0)
 *
 * What it does:
 * Destroys text-style subobjects in reverse order.
 */
wxTextAttrRuntime::~wxTextAttrRuntime() = default;

msvc8::string wxTextCtrlRuntime::GetValueUtf8() const
{
  return GetValue().ToUtf8();
}

msvc8::string wxTextCtrlRuntime::GetValueUtf8Lower() const
{
  return GetValue().ToUtf8Lower();
}

void wxTextCtrlRuntime::SetValueUtf8(
  const msvc8::string& value
)
{
  const std::wstring wideValue = gpg::STR_Utf8ToWide(value.c_str());
  SetValue(wxStringRuntime::Borrow(wideValue.c_str()));
}

void wxTextCtrlRuntime::AppendUtf8(
  const msvc8::string& text
)
{
  const std::wstring wideText = gpg::STR_Utf8ToWide(text.c_str());
  AppendText(wxStringRuntime::Borrow(wideText.c_str()));
}

void wxTextCtrlRuntime::AppendWide(
  const std::wstring& text
)
{
  AppendText(wxStringRuntime::Borrow(text.c_str()));
}

void wxTextCtrlRuntime::ScrollToLastPosition()
{
  ShowPosition(GetLastPosition());
}

/**
 * Address: 0x004F73B0 (FUN_004F73B0)
 *
 * What it does:
 * Constructs one wide stream/buffer helper used by log-window text formatting.
 */
moho::WWinLogTextBuilder::WWinLogTextBuilder() = default;

/**
 * Address: 0x004F74D0 (FUN_004F74D0)
 *
 * What it does:
 * Finalizes stream state and returns the accumulated wide text.
 */
const std::wstring& moho::WWinLogTextBuilder::Finalize() const noexcept
{
  return mText;
}

void moho::WWinLogTextBuilder::SetFieldWidth(
  const std::size_t width
) noexcept
{
  mFieldWidth = width;
}

void moho::WWinLogTextBuilder::Clear() noexcept
{
  mText.clear();
  mFieldWidth = 0;
  mFillCodePoint = L' ';
  mLeftAlign = false;
}

/**
 * Address: 0x004F98F0 (FUN_004F98F0)
 *
 * What it does:
 * Emits one code-point with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteCodePoint(
  const wchar_t codePoint
)
{
  const std::wstring oneCodePoint(1, codePoint);
  WriteWideText(oneCodePoint);
}

/**
 * Address: 0x004F9B80 (FUN_004F9B80)
 *
 * What it does:
 * Emits one wide string with optional field-width padding and clears transient
 * width state.
 */
void moho::WWinLogTextBuilder::WriteWideText(
  const std::wstring& text
)
{
  const std::size_t paddingCount = mFieldWidth > text.size() ? mFieldWidth - text.size() : 0;
  if (!mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mText += text;

  if (mLeftAlign && paddingCount != 0) {
    mText.append(paddingCount, mFillCodePoint);
  }

  mFieldWidth = 0;
}

/**
 * Address: 0x004F9DF0 (FUN_004F9DF0)
 *
 * What it does:
 * Emits one wide-string literal with width/padding behavior.
 */
void moho::WWinLogTextBuilder::WriteWideLiteral(
  const wchar_t* const text
)
{
  WriteWideText(text != nullptr ? std::wstring(text) : std::wstring{});
}

/**
 * Address: 0x004FA000 (FUN_004FA000)
 *
 * What it does:
 * Emits one UTF-8 fragment by widening it then appending with width behavior.
 */
void moho::WWinLogTextBuilder::WriteUtf8Text(
  const msvc8::string& text
)
{
  WriteWideText(gpg::STR_Utf8ToWide(text.c_str()));
}

/**
 * Address: 0x004FA2C0 (FUN_004FA2C0)
 *
 * What it does:
 * Emits one decoded wide code-point.
 */
void moho::WWinLogTextBuilder::WriteDecodedCodePoint(
  const wchar_t codePoint
)
{
  WriteCodePoint(codePoint);
}

/**
 * Address: 0x004F5AB0 (FUN_004F5AB0)
 *
 * What it does:
 * Emits one run of space code-points.
 */
void moho::WWinLogTextBuilder::WriteSpaces(
  std::size_t count
)
{
  while (count > 0) {
    WriteCodePoint(L' ');
    --count;
  }
}

bool moho::CWinLogLine::IsReplayEntry() const noexcept
{
  return isReplayEntry != 0u;
}

bool moho::CWinLogLine::IsMessageEntry() const noexcept
{
  return !IsReplayEntry();
}

const wchar_t* moho::CWinLogLine::SeverityPrefix() const noexcept
{
  switch (categoryMask) {
  case 0u:
    return L"DEBUG: ";
  case kWarningCategoryValue:
    return L"WARNING: ";
  case kErrorCategoryValue:
    return L"ERROR: ";
  default:
    return L"INFO: ";
  }
}

/**
 * Address: 0x00978FF0 (FUN_00978FF0, ??0wxEvent@@QAE@@Z)
 *
 * What it does:
 * Initializes one wxEvent runtime payload from `(eventId, eventType)` and
 * clears ref/object/timestamp/flag lanes.
 */
wxEventRuntime::wxEventRuntime(
  const std::int32_t eventId,
  const std::int32_t eventType
)
  : mRefData(nullptr)
  , mEventObject(nullptr)
  , mEventType(eventType)
  , mEventTimestamp(0)
  , mEventId(eventId)
  , mCallbackUserData(nullptr)
  , mSkipped(0)
  , mIsCommandEvent(0)
  , mReserved1E(0)
  , mReserved1F(0)
{}

/**
 * Address: 0x00979090 (FUN_00979090, ??0wxCommandEvent@@QAE@@Z)
 *
 * What it does:
 * Initializes one wxCommandEvent payload on top of wxEvent runtime state and
 * sets the command-event marker flag.
 */
wxCommandEventRuntime::wxCommandEventRuntime(
  const std::int32_t commandType,
  const std::int32_t eventId
)
  : wxEventRuntime(eventId, commandType)
  , mCommandString(wxStringRuntime::Borrow(L""))
  , mCommandInt(0)
  , mExtraLong(0)
  , mClientData(nullptr)
  , mClientObject(nullptr)
{
  mIsCommandEvent = 1u;
}

/**
 * Address: 0x006609B0 (FUN_006609B0, ??1wxCommandEvent@@QAE@@Z)
 *
 * What it does:
 * Releases one shared command-string payload and clears wxEvent ref-data
 * ownership via the base unref tail.
 */
wxCommandEventRuntime::~wxCommandEventRuntime()
{
  ReleaseWxStringSharedPayload(mCommandString);
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
}

/**
 * Address: 0x00987D00 (FUN_00987D00, ??1wxListItem@@QAE@@Z)
 * Mangled: ??1wxListItem@@QAE@@Z
 *
 * What it does:
 * Releases optional list-item attribute storage, releases shared string
 * payload ownership, and clears base wxObject ref-data ownership lanes.
 */
wxListItemRuntime::~wxListItemRuntime()
{
  if (mAttr != nullptr) {
    DestroyWxListItemAttrRuntime(mAttr);
    ::operator delete(mAttr);
    mAttr = nullptr;
  }

  ReleaseWxStringSharedPayload(mText);
  RunWxObjectUnrefTail(reinterpret_cast<WxObjectRuntimeView*>(this));
}

/**
 * Address: 0x0099D120 (FUN_0099D120, wxListCtrl::GetItemData)
 *
 * What it does:
 * Builds one stack `wxListItem` request payload (mask=0x8 for data lane),
 * queries the row through `GetItem`, and returns row user-data on success.
 */
long wxListCtrlRuntime::GetItemData(
  const std::int32_t itemId
)
{
  wxListItemRuntime item{};
  item.mMask = 0x8;
  item.mItemId = itemId;
  item.mColumn = 0;
  item.mState = 0;
  item.mStateMask = 0;
  item.mImage = 0;
  item.mData = 0;
  item.mFormat = 2;
  item.mWidth = 0;
  item.mAttr = nullptr;

  if (!GetItem(&item)) {
    return 0;
  }

  return item.mData;
}

/**
 * Address: 0x00978190 (FUN_00978190, func_wxNodeBaseInit)
 *
 * What it does:
 * Initializes one `wxNodeBase` node with key/data/owner lanes and links it
 * between optional neighboring nodes.
 */
wxNodeBaseRuntime* wxNodeBaseInit(
  wxNodeBaseRuntime* const node,
  void* const listOwner,
  wxNodeBaseRuntime* const previous,
  wxNodeBaseRuntime* const next,
  void* const value,
  const wxListKeyRuntime* const key
)
{
  if (node == nullptr) {
    return nullptr;
  }

  new (node) wxNodeBaseRuntime();
  node->mValue = value;
  node->mListOwner = listOwner;
  node->mPrevious = previous;
  node->mNext = next;

  if (key != nullptr) {
    if (key->mKeyType == wxKEY_INTEGER_RUNTIME) {
      node->mKeyStorage = key->mKey.integer;
    } else if (key->mKeyType == wxKEY_STRING_RUNTIME && key->mKey.string != nullptr) {
      node->mKeyStorage = reinterpret_cast<std::uintptr_t>(::_wcsdup(key->mKey.string));
    }
  }

  if (previous != nullptr) {
    previous->mNext = node;
  }
  if (next != nullptr) {
    next->mPrevious = node;
  }

  return node;
}

/**
 * Address: 0x004F38E0 (FUN_004F38E0)
 *
 * What it does:
 * Returns the static wx class-info lane for this event payload type.
 */
void* moho::CLogAdditionEvent::GetClassInfo() const
{
  return gCLogAdditionEventClassInfoTable;
}

/**
 * Address: 0x004F3850 (FUN_004F3850)
 *
 * What it does:
 * Deleting-dtor entry for this event payload type.
 */
void moho::CLogAdditionEvent::DeleteObject()
{
  delete this;
}

/**
 * Address: 0x004F37F0 (FUN_004F37F0)
 *
 * What it does:
 * Allocates and copy-clones one `CLogAdditionEvent` object.
 */
moho::CLogAdditionEvent* moho::CLogAdditionEvent::Clone() const
{
  return new CLogAdditionEvent(*this);
}

/**
 * Address: 0x004F38F0 (FUN_004F38F0, ??0CWinLogTarget@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes the global log-target owner and auto-registers it with gpg logging.
 */
moho::CWinLogTarget::CWinLogTarget()
  : gpg::LogTarget(true)
{}

/**
 * Address: 0x004F39B0 (FUN_004F39B0)
 * Mangled deleting-dtor thunk: 0x004F3990 (FUN_004F3990)
 *
 * What it does:
 * Releases pending/committed vectors and tears down base log-target registration.
 */
moho::CWinLogTarget::~CWinLogTarget() = default;

/**
 * Address: 0x004F6F40 (FUN_004F6F40)
 *
 * What it does:
 * Appends one line record into the pending queue.
 */
void moho::CWinLogTarget::AppendPendingLine(
  const CWinLogLine& line
)
{
  mPendingLines.push_back(line);
}

/**
 * Address: 0x004F6F10 (FUN_004F6F10)
 *
 * What it does:
 * Returns committed line count.
 */
std::size_t moho::CWinLogTarget::CommittedLineCount() const
{
  return mCommittedLines.size();
}

const msvc8::vector<moho::CWinLogLine>& moho::CWinLogTarget::CommittedLines() const
{
  return mCommittedLines;
}

/**
 * Address: 0x004F6FD0 (FUN_004F6FD0)
 *
 * What it does:
 * Replaces committed-line storage with a copy of `nextCommittedLines`.
 */
void moho::CWinLogTarget::ReplaceCommittedLines(
  const msvc8::vector<CWinLogLine>& nextCommittedLines
)
{
  mCommittedLines = nextCommittedLines;
}

void moho::CWinLogTarget::SnapshotCommittedLines(
  msvc8::vector<CWinLogLine>* const outLines
)
{
  if (outLines == nullptr) {
    return;
  }

  boost::mutex::scoped_lock scopedLock(lock);
  *outLines = mCommittedLines;
}

void moho::CWinLogTarget::ResetCommittedLinesFromReplayBuffer(
  const msvc8::vector<msvc8::string>& replayLines
)
{
  boost::mutex::scoped_lock scopedLock(lock);

  msvc8::vector<CWinLogLine> rebuiltLines;
  rebuiltLines.reserve(replayLines.size());
  for (std::size_t index = 0; index < replayLines.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = 1;
    replayLine.text = replayLines[index];
    rebuiltLines.push_back(replayLine);
  }

  ReplaceCommittedLines(rebuiltLines);
}

/**
 * Address: 0x004F6A50 (FUN_004F6A50)
 *
 * What it does:
 * Merges pending lines into committed history and enforces the 10,000 line cap.
 */
void moho::CWinLogTarget::MergePendingLines()
{
  boost::mutex::scoped_lock scopedLock(lock);

  const std::size_t pendingCount = mPendingLines.size();
  const std::size_t committedCount = mCommittedLines.size();
  if (committedCount + pendingCount > kMaxCommittedLogLines) {
    const std::size_t dropCount = (std::min)(committedCount, pendingCount);
    if (dropCount != 0) {
      mCommittedLines.erase(mCommittedLines.begin(), mCommittedLines.begin() + dropCount);
    }
  }

  for (const CWinLogLine& line : mPendingLines) {
    mCommittedLines.push_back(line);
  }
  mPendingLines.clear();
}

/**
 * Address: 0x004F6860 (FUN_004F6860)
 *
 * gpg::LogSeverity level, msvc8::string const &, msvc8::vector<msvc8::string> const &, int
 *
 * What it does:
 * Queues replay/context lines plus the current line into the pending log queue.
 */
void moho::CWinLogTarget::OnMessage(
  const gpg::LogSeverity level,
  const msvc8::string& message,
  const msvc8::vector<msvc8::string>& context,
  const int previousDepth
)
{
  boost::mutex::scoped_lock scopedLock(lock);

  std::size_t replayStart = 0;
  if (previousDepth > 0) {
    replayStart = static_cast<std::size_t>(previousDepth);
  }
  if (replayStart > context.size()) {
    replayStart = context.size();
  }

  const std::uint32_t categoryMask = static_cast<std::uint32_t>(level);
  for (std::size_t index = replayStart; index < context.size(); ++index) {
    CWinLogLine replayLine{};
    replayLine.isReplayEntry = 1;
    replayLine.sequenceIndex = static_cast<std::uint32_t>(index);
    replayLine.categoryMask = categoryMask;
    replayLine.text = context[index];
    AppendPendingLine(replayLine);
  }

  CWinLogLine messageLine{};
  messageLine.isReplayEntry = 0;
  messageLine.sequenceIndex = static_cast<std::uint32_t>(context.size());
  messageLine.categoryMask = categoryMask;
  messageLine.text = message;
  AppendPendingLine(messageLine);

  WWinLogWindow* const dialogWindow = dialog;
  scopedLock.unlock();
  if (dialogWindow != nullptr) {
    const CLogAdditionEvent event{};
    dialogWindow->OnTargetPendingLinesChanged(event);
  }
}

/**
 * Address: 0x004F4270 (FUN_004F4270)
 *
 * What it does:
 * Constructs one managed log-window object and seeds control/runtime state
 * lanes used by downstream append/rebuild handlers.
 */
moho::WWinLogWindow::WWinLogWindow()
{
  mIsInitializingControls = 1;
  mEnabledCategoriesMask = 0;
  mFilterText.clear();
  mBufferedLines.clear();
  mFirstVisibleLine = 0;
  RegisterManagedOwnerSlot();
  InitializeFromUserPreferences();
  mIsInitializingControls = 0;
}

void moho::WWinLogWindow::InitializeFromUserPreferences()
{
  IUserPrefs* const preferences = USER_GetPreferences();
  RestoreCategoryStateFromPreferences(preferences);
  RestoreFilterFromPreferences(preferences);
  RestoreGeometryFromPreferences(preferences);
}

void moho::WWinLogWindow::RestoreCategoryStateFromPreferences(
  IUserPrefs* const preferences
)
{
  mEnabledCategoriesMask = 0;

  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    const bool enabled = preferences != nullptr
      ? preferences->GetBoolean(msvc8::string(kLogCategoryPreferenceKeys[index]), kLogCategoryPreferenceDefaults[index])
      : kLogCategoryPreferenceDefaults[index];

    if (enabled) {
      mEnabledCategoriesMask |= (1u << static_cast<std::uint32_t>(index));
    }

    if (checkBoxes[index] != nullptr) {
      checkBoxes[index]->SetValue(enabled);
    }
  }
}

void moho::WWinLogWindow::RestoreFilterFromPreferences(
  IUserPrefs* const preferences
)
{
  const msvc8::string fallback(kLogFilterPreferenceDefault);
  if (preferences != nullptr) {
    mFilterText = preferences->GetString(msvc8::string(kLogFilterPreferenceKey), fallback);
  } else {
    mFilterText = fallback;
  }

  if (mFilterTextControl != nullptr) {
    mFilterTextControl->SetValueUtf8(mFilterText);
  }
}

void moho::WWinLogWindow::RestoreGeometryFromPreferences(
  IUserPrefs* const preferences
)
{
  if (preferences == nullptr) {
    return;
  }

  const std::int32_t height =
    preferences->GetInteger(msvc8::string(kLogWindowHeightPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t width =
    preferences->GetInteger(msvc8::string(kLogWindowWidthPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t y = preferences->GetInteger(msvc8::string(kLogWindowYPreferenceKey), kLogWindowGeometryFallback);
  const std::int32_t x = preferences->GetInteger(msvc8::string(kLogWindowXPreferenceKey), kLogWindowGeometryFallback);

  DoSetSize(x, y, width, height, kLogWindowSetSizeFlags);
}

/**
 * Address: 0x004F5380 (FUN_004F5380)
 * Mangled deleting-dtor thunk: 0x004F5360 (FUN_004F5360)
 *
 * What it does:
 * Detaches from the owner log target, clears local storage lanes, and unlinks
 * managed-owner slots.
 */
moho::WWinLogWindow::~WWinLogWindow()
{
  DetachFromTarget();
  mBufferedLines.clear();
  mFilterText.clear();
  ReleaseManagedOwnerSlots();
}

void moho::WWinLogWindow::SetOwnerTarget(
  CWinLogTarget* const ownerTarget
) noexcept
{
  mOwnerTarget = ownerTarget;
}

/**
 * Address: 0x004F6760 (FUN_004F6760)
 *
 * What it does:
 * Clears `mOwnerTarget->dialog` under the target lock.
 */
void moho::WWinLogWindow::DetachFromTarget()
{
  if (mOwnerTarget == nullptr) {
    return;
  }

  boost::mutex::scoped_lock scopedLock(mOwnerTarget->lock);
  mOwnerTarget->dialog = nullptr;
}

std::array<wxCheckBoxRuntime*, 5> moho::WWinLogWindow::CategoryCheckBoxes() noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

std::array<const wxCheckBoxRuntime*, 5> moho::WWinLogWindow::CategoryCheckBoxes() const noexcept
{
  return {
    mDebugCategoryCheckBox,
    mInfoCategoryCheckBox,
    mWarnCategoryCheckBox,
    mErrorCategoryCheckBox,
    mCustomCategoryCheckBox,
  };
}

/**
 * Address: 0x004F5440 (FUN_004F5440)
 *
 * What it does:
 * Clears output and rebuilds committed target lines from buffered replay text
 * entries.
 */
void moho::WWinLogWindow::ResetCommittedLinesFromBuffer()
{
  if (mOutputTextControl != nullptr) {
    mOutputTextControl->Clear();
  }

  mFirstVisibleLine = 0;

  if (mOwnerTarget == nullptr) {
    return;
  }

  mOwnerTarget->ResetCommittedLinesFromReplayBuffer(mBufferedLines);
}

bool moho::WWinLogWindow::ShouldDisplayCommittedLine(
  const CWinLogLine& line
) const
{
  if (line.categoryMask < 32) {
    const std::uint32_t categoryBit = 1u << line.categoryMask;
    if ((mEnabledCategoriesMask & categoryBit) != 0u) {
      return true;
    }
  }

  if ((mEnabledCategoriesMask & kCustomFilterCategoryBit) == 0u) {
    return false;
  }

  const msvc8::string loweredLineText = gpg::STR_ToLower(line.text.c_str());
  return std::strstr(loweredLineText.c_str(), mFilterText.c_str()) != nullptr;
}

std::wstring moho::WWinLogWindow::BuildReplayFlushText(
  const std::size_t startIndex
) const
{
  WWinLogTextBuilder replayBuilder{};
  for (std::size_t index = startIndex; index < mBufferedLines.size(); ++index) {
    replayBuilder.WriteSpaces(index * kReplayIndentWidth);
    replayBuilder.WriteUtf8Text(mBufferedLines[index]);
    replayBuilder.WriteCodePoint(L'\n');
  }

  return replayBuilder.Finalize();
}

std::wstring moho::WWinLogWindow::BuildFormattedCommittedLineText(
  const CWinLogLine& line
) const
{
  WWinLogTextBuilder lineBuilder{};
  const std::wstring severityPrefix(line.SeverityPrefix());
  lineBuilder.WriteWideText(severityPrefix);

  const std::size_t continuationIndent = mBufferedLines.size() * kReplayIndentWidth + severityPrefix.size();
  bool continuationLine = false;
  wchar_t decodedCodePoint = 0;
  const char* cursor = gpg::STR_DecodeUtf8Char(line.text.c_str(), decodedCodePoint);
  while (decodedCodePoint != 0) {
    if (continuationLine) {
      lineBuilder.WriteSpaces(continuationIndent);
      continuationLine = false;
    }

    lineBuilder.WriteDecodedCodePoint(decodedCodePoint);
    if (decodedCodePoint == L'\n') {
      continuationLine = true;
    }

    cursor = gpg::STR_DecodeUtf8Char(cursor, decodedCodePoint);
  }

  if (!continuationLine) {
    lineBuilder.WriteCodePoint(L'\n');
  }

  return lineBuilder.Finalize();
}

/**
 * Address: 0x004F5840 (FUN_004F5840)
 *
 * What it does:
 * Rebuilds category/filter visibility state from controls and replays matching
 * committed lines into output.
 */
void moho::WWinLogWindow::RebuildVisibleLinesFromControls()
{
  mEnabledCategoriesMask = 0;
  const auto checkBoxes = CategoryCheckBoxes();
  for (std::size_t index = 0; index < checkBoxes.size(); ++index) {
    const wxCheckBoxRuntime* const checkBox = checkBoxes[index];
    if (checkBox != nullptr && checkBox->GetValue()) {
      mEnabledCategoriesMask |= (1u << index);
    }
  }

  if (mFilterTextControl != nullptr) {
    mFilterText = mFilterTextControl->GetValueUtf8Lower();
  } else {
    mFilterText.clear();
  }

  if (mOutputTextControl != nullptr) {
    mOutputTextControl->Clear();
  }

  mFirstVisibleLine = 0;
  mBufferedLines.clear();

  if (mOwnerTarget == nullptr) {
    return;
  }

  msvc8::vector<CWinLogLine> committedLinesSnapshot;
  mOwnerTarget->SnapshotCommittedLines(&committedLinesSnapshot);

  for (const CWinLogLine& line : committedLinesSnapshot) {
    AppendCommittedLine(line);
  }

  if (mOutputTextControl != nullptr) {
    mOutputTextControl->ScrollToLastPosition();
  }
}

/**
 * Address: 0x004F5AE0 (FUN_004F5AE0)
 *
 * What it does:
 * Applies one committed line against category/filter visibility and appends
 * replay/text output with preserved indentation behavior.
 */
void moho::WWinLogWindow::AppendCommittedLine(
  const CWinLogLine& line
)
{
  while (mBufferedLines.size() > line.sequenceIndex) {
    mBufferedLines.pop_back();
  }

  if (mFirstVisibleLine > mBufferedLines.size()) {
    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
  }

  if (line.IsReplayEntry()) {
    if (line.isReplayEntry == 1u) {
      mBufferedLines.push_back(line.text);
    }
    return;
  }

  if (!ShouldDisplayCommittedLine(line)) {
    return;
  }

  if (mOutputTextControl == nullptr) {
    return;
  }

  if (mFirstVisibleLine < mBufferedLines.size()) {
    const wxTextAttrRuntime replayStyle = DefaultTextStyleForCategory(1u);
    (void)mOutputTextControl->SetDefaultStyle(replayStyle);
    const std::wstring replayText = BuildReplayFlushText(mFirstVisibleLine);

    mFirstVisibleLine = static_cast<std::uint32_t>(mBufferedLines.size());
    if (!replayText.empty()) {
      mOutputTextControl->AppendWide(replayText);
    }
  }

  const wxTextAttrRuntime lineStyle = DefaultTextStyleForCategory(line.categoryMask);
  (void)mOutputTextControl->SetDefaultStyle(lineStyle);
  const std::wstring formattedText = BuildFormattedCommittedLineText(line);
  mOutputTextControl->AppendWide(formattedText);

  if (line.categoryMask >= kWarningCategoryValue && moho::CFG_GetArgOption("/edit", 0, nullptr)) {
    Show(true);
  }
}

/**
 * Address: 0x004F6470 (FUN_004F6470)
 *
 * What it does:
 * Merges pending lines into committed history and refreshes output when the
 * committed count changed.
 */
void moho::WWinLogWindow::OnTargetPendingLinesChanged(
  const CLogAdditionEvent& event
)
{
  (void)event;
  if (mOwnerTarget == nullptr) {
    return;
  }

  const std::size_t previousCommittedLineCount = mOwnerTarget->CommittedLineCount();
  mOwnerTarget->MergePendingLines();
  if (previousCommittedLineCount != mOwnerTarget->CommittedLineCount()) {
    RebuildVisibleLinesFromControls();
  }
}

void moho::WWinLogWindow::OnTargetPendingLinesChanged()
{
  const CLogAdditionEvent event{};
  OnTargetPendingLinesChanged(event);
}

/**
 * Address: 0x008CD8C0 (FUN_008CD8C0)
 * Mangled: ??0WSupComFrame@@QAE@PBDABVwxPoint@@ABVwxSize@@J@Z
 *
 * What it does:
 * Creates one SupCom frame runtime object with constructor-equivalent startup
 * semantics: UTF-8 title lane, position/style lanes, sync-flag zeroing,
 * min-drag size hints, and startup icon-resource assignment.
 */
WSupComFrame* WX_CreateSupComFrame(
  const char* const title,
  const wxPoint& position,
  const wxSize& size,
  const std::int32_t style
)
{
  auto* const frame = new WSupComFrameRuntime(title, position, size, style);
  frame->SetSizeHints(moho::wnd_MinDragWidth, moho::wnd_MinDragHeight, -1, -1, -1, -1);
  return frame;
}

namespace
{
  constexpr unsigned int kSupComFrameMessageSize = WM_SIZE;
  constexpr unsigned int kSupComFrameMessageActivateApp = WM_ACTIVATEAPP;
  constexpr unsigned int kSupComFrameMessageSysCommand = WM_SYSCOMMAND;
  constexpr unsigned int kSupComFrameMessageExitSizeMove = WM_EXITSIZEMOVE;
  constexpr unsigned int kSupComFrameSysCommandToggleLogDialog = 0x1u;
  constexpr unsigned int kSupComFrameSysCommandLuaDebugger = 0x2u;
  constexpr unsigned int kSupComFrameSysCommandKeyMenu = SC_KEYMENU;

  constexpr const char* kSupComFrameXPreferenceKey = "Windows.Main.x";
  constexpr const char* kSupComFrameYPreferenceKey = "Windows.Main.y";
  constexpr const char* kSupComFrameWidthPreferenceKey = "Windows.Main.width";
  constexpr const char* kSupComFrameHeightPreferenceKey = "Windows.Main.height";
  constexpr const char* kSupComFrameMaximizedPreferenceKey = "Windows.Main.maximized";
  constexpr const char* kSupComFrameToggleLogDialogCommand = "WIN_ToggleLogDialog";
  constexpr const char* kSupComFrameLuaDebuggerCommand = "SC_LuaDebugger";
  constexpr const char* kSupComFrameCursorLockPreferenceKey = "lock_fullscreen_cursor_to_window";

  /**
   * Address: 0x008CDBE0 (FUN_008CDBE0)
   *
   * What it does:
   * Clamps SupCom frame client dimensions to drag minima, propagates size to
   * the active viewport, then rebuilds one GAL context head and reinitializes
   * D3D device state.
   */
  void SyncSupComFrameClientSizeAndViewport(
    WSupComFrame& frame
  )
  {
    std::int32_t width = 0;
    std::int32_t height = 0;
    frame.DoGetClientSize(&width, &height);

    if (width < moho::wnd_MinDragWidth) {
      width = moho::wnd_MinDragWidth;
    }
    if (height < moho::wnd_MinDragHeight) {
      height = moho::wnd_MinDragHeight;
    }

    frame.DoSetClientSize(width, height);
    if (moho::ren_Viewport != nullptr) {
      moho::ren_Viewport->DoSetSize(-1, -1, width, height, 0);
    }

    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() > 0) {
      gpg::gal::Head& head = context.GetHead(0);
      head.mWidth = width;
      head.mHeight = height;
    }

    moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice();
    if (d3dDevice == nullptr) {
      return;
    }

    d3dDevice->Clear();
    d3dDevice->InitContext(&context);
  }

  /**
   * Address: 0x008D1D70 (FUN_008D1D70)
   *
   * What it does:
   * Applies cursor clipping for active SupCom frame focus: locks to main
   * window rectangle when one windowed head is active and the cursor-lock
   * option is enabled, otherwise clears clip bounds.
   */
  void UpdateSupComCursorClipForActivation()
  {
    gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
    if (galDevice == nullptr) {
      return;
    }

    gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
    if (activeContext == nullptr) {
      return;
    }

    gpg::gal::DeviceContext context(*activeContext);
    if (context.GetHeadCount() <= 0) {
      return;
    }

    const gpg::gal::Head& head = context.GetHead(0);
    RECT clipRect{};
    RECT* clipRectPtr = nullptr;
    if (
      context.GetHeadCount() == 1 && head.mWindowed && moho::OPTIONS_GetInt(kSupComFrameCursorLockPreferenceKey) == 1 &&
      moho::sMainWindow != nullptr
    ) {
      const HWND mainWindowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
      if (mainWindowHandle != nullptr) {
        ::GetWindowRect(mainWindowHandle, &clipRect);
        clipRectPtr = &clipRect;
      }
    }

    ::ClipCursor(clipRectPtr);
  }
} // namespace

/**
 * Address: 0x008CDAD0 (FUN_008CDAD0, WSupComFrame::OnMove)
 *
 * What it does:
 * Persists SupCom frame position lanes to user preferences while device-lock
 * is disabled and the frame is not iconized.
 */
void WSupComFrame::OnMove(
  wxMoveEventRuntime& event
)
{
  (void)event;
  if (moho::sDeviceLock || IsIconized()) {
    return;
  }

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (preferences == nullptr) {
    return;
  }

  std::int32_t positionLaneA = 0;
  std::int32_t positionLaneB = 0;

  DoGetPosition(&positionLaneA, &positionLaneB);
  preferences->SetInteger(msvc8::string(kSupComFrameXPreferenceKey), positionLaneB);

  DoGetPosition(&positionLaneA, &positionLaneB);
  preferences->SetInteger(msvc8::string(kSupComFrameYPreferenceKey), positionLaneA);
}

/**
 * Address: 0x008CDD40 (FUN_008CDD40, WSupComFrame::MSWWindowProc)
 * Mangled: ?MSWWindowProc@WSupComFrame@@UAEJIIJ@Z
 *
 * What it does:
 * Handles SupCom frame resize/maximize/app-activation/system-command routing,
 * persists window preference keys, and forwards unhandled messages to base
 * frame dispatch.
 */
long WSupComFrame::MSWWindowProc(
  const unsigned int message,
  const unsigned int wParam,
  const long lParam
)
{
  auto dispatchBase = [this, message, wParam, lParam]() -> long {
    return wxTopLevelWindowRuntime::MSWWindowProc(message, wParam, lParam);
  };

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (!moho::sDeviceLock && moho::ren_Viewport != nullptr && gpg::gal::Device::IsReady()) {
    if (gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance(); galDevice != nullptr) {
      if (
        gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
        activeContext != nullptr && activeContext->GetHeadCount() > 0
      ) {
        (void)activeContext->GetHead(0);
      }
    }

    if (mPendingMaximizeSync != 0 && message == kSupComFrameMessageExitSizeMove) {
      SyncSupComFrameClientSizeAndViewport(*this);

      if (preferences != nullptr) {
        const wxSize clientSize = GetClientSize();
        preferences->SetInteger(msvc8::string(kSupComFrameWidthPreferenceKey), clientSize.x);
        preferences->SetInteger(msvc8::string(kSupComFrameHeightPreferenceKey), clientSize.y);
      }

      if (moho::CD3DDevice* const d3dDevice = moho::D3D_GetDevice(); d3dDevice != nullptr) {
        (void)d3dDevice->Clear2(false);
      }

      mPendingMaximizeSync = 0;
    } else if (message == kSupComFrameMessageSize && wParam == SIZE_MAXIMIZED) {
      SyncSupComFrameClientSizeAndViewport(*this);
      if (preferences != nullptr) {
        preferences->SetBoolean(msvc8::string(kSupComFrameMaximizedPreferenceKey), true);
      }
      mPersistedMaximizeSync = 1;
    }

    if (mPendingMaximizeSync == 0 && message == kSupComFrameMessageSize) {
      if (wParam == SIZE_RESTORED && mPersistedMaximizeSync != 0) {
        SyncSupComFrameClientSizeAndViewport(*this);
        if (preferences != nullptr) {
          const wxSize clientSize = GetClientSize();
          preferences->SetInteger(msvc8::string(kSupComFrameWidthPreferenceKey), clientSize.x);
          preferences->SetInteger(msvc8::string(kSupComFrameHeightPreferenceKey), clientSize.y);
          preferences->SetBoolean(msvc8::string(kSupComFrameMaximizedPreferenceKey), false);
        }
        mPersistedMaximizeSync = 0;
      }

      return dispatchBase();
    }
  }

  if (message == kSupComFrameMessageActivateApp) {
    const bool isActive = wParam != 0;
    mIsApplicationActive = isActive ? 1 : 0;
    if (isActive) {
      UpdateSupComCursorClipForActivation();
    } else {
      ::ClipCursor(nullptr);
    }
    return dispatchBase();
  }

  if (message != kSupComFrameMessageSysCommand) {
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandToggleLogDialog) {
    moho::CON_Execute(kSupComFrameToggleLogDialogCommand);
    return dispatchBase();
  }

  if (wParam == kSupComFrameSysCommandLuaDebugger) {
    moho::CON_Execute(kSupComFrameLuaDebuggerCommand);
    return dispatchBase();
  }

  if (wParam != kSupComFrameSysCommandKeyMenu) {
    return dispatchBase();
  }

  gpg::gal::Device* const galDevice = gpg::gal::Device::GetInstance();
  if (galDevice == nullptr) {
    return dispatchBase();
  }

  gpg::gal::DeviceContext* const activeContext = galDevice->GetDeviceContext();
  if (activeContext == nullptr || activeContext->GetHeadCount() <= 0 || !activeContext->GetHead(0).mWindowed) {
    return dispatchBase();
  }

  return 0;
}

/**
 * Address family:
 * - 0x004F7210 (FUN_004F7210)
 * - 0x004F72D0 (FUN_004F72D0)
 *
 * What it does:
 * Unlinks one managed slot from its owner slot chain.
 */
void moho::ManagedWindowSlot::UnlinkFromOwner() noexcept
{
  if (ownerHeadLink == nullptr || IsInlineHeadLinkSentinel(ownerHeadLink)) {
    ownerHeadLink = nullptr;
    nextInOwnerChain = nullptr;
    return;
  }

  ManagedWindowSlot** link = ownerHeadLink;
  while (*link != this) {
    if (*link == nullptr) {
      ownerHeadLink = nullptr;
      nextInOwnerChain = nullptr;
      return;
    }
    link = &(*link)->nextInOwnerChain;
  }

  *link = nextInOwnerChain;
  ownerHeadLink = nullptr;
  nextInOwnerChain = nullptr;
}

/**
 * Address context:
 * - destructor slot-clear writes in 0x004F40A0 / 0x004F4230
 *
 * What it does:
 * Clears both link lanes to the inert slot state.
 */
void moho::ManagedWindowSlot::Clear() noexcept
{
  ownerHeadLink = nullptr;
  nextInOwnerChain = nullptr;
}

moho::WWinManagedDialog* moho::WWinManagedDialog::FromManagedSlotHeadLink(
  ManagedWindowSlot** const ownerHeadLink
) noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == NullManagedSlotHeadLinkSentinel()) {
    return nullptr;
  }

  const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  return reinterpret_cast<WWinManagedDialog*>(linkAddress - offsetof(WWinManagedDialog, mManagedSlotsHead));
}

moho::ManagedWindowSlot** moho::WWinManagedDialog::NullManagedSlotHeadLinkSentinel() noexcept
{
  return reinterpret_cast<ManagedWindowSlot**>(offsetof(WWinManagedDialog, mManagedSlotsHead));
}

/**
 * Address: 0x004F7070 (FUN_004F7070)
 *
 * What it does:
 * Returns the current number of dialog-managed registry slots.
 */
std::size_t moho::WWinManagedDialog::ManagedSlotCount()
{
  return managedWindows.size();
}

/**
 * Address: 0x004F70A0 (FUN_004F70A0)
 *
 * What it does:
 * Appends one dialog-managed registry slot and links it to `ownerHeadLink`.
 */
void moho::WWinManagedDialog::AppendManagedSlotForOwner(
  ManagedWindowSlot** const ownerHeadLink
)
{
  AppendManagedSlot<WWinManagedDialog>(managedWindows, ownerHeadLink);
}

/**
 * Address: 0x004F3F50 (FUN_004F3F50, WWinManagedDialog ctor tail)
 *
 * What it does:
 * Registers this dialog owner head in the global managed-dialog slot registry.
 */
void moho::WWinManagedDialog::RegisterManagedOwnerSlot()
{
  RegisterManagedOwnerSlotImpl<WWinManagedDialog>(managedWindows, &mManagedSlotsHead);
}

/**
 * Address: 0x004F40A0 (FUN_004F40A0, WWinManagedDialog dtor core)
 *
 * What it does:
 * Unlinks and clears every managed slot currently chained to this dialog.
 */
void moho::WWinManagedDialog::ReleaseManagedOwnerSlots()
{
  ReleaseManagedOwnerSlotChain(mManagedSlotsHead);
}

void moho::WWinManagedDialog::DestroyManagedOwners(
  msvc8::vector<ManagedWindowSlot>& slots
)
{
  DestroyManagedRuntimeCollection<WWinManagedDialog>(slots);
}

moho::WWinManagedFrame* moho::WWinManagedFrame::FromManagedSlotHeadLink(
  ManagedWindowSlot** const ownerHeadLink
) noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == NullManagedSlotHeadLinkSentinel()) {
    return nullptr;
  }

  const std::uintptr_t linkAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  return reinterpret_cast<WWinManagedFrame*>(linkAddress - offsetof(WWinManagedFrame, mManagedSlotsHead));
}

moho::ManagedWindowSlot** moho::WWinManagedFrame::NullManagedSlotHeadLinkSentinel() noexcept
{
  return reinterpret_cast<ManagedWindowSlot**>(offsetof(WWinManagedFrame, mManagedSlotsHead));
}

/**
 * Address: 0x004F7140 (FUN_004F7140)
 *
 * What it does:
 * Returns the current number of frame-managed registry slots.
 */
std::size_t moho::WWinManagedFrame::ManagedSlotCount()
{
  return managedFrames.size();
}

/**
 * Address: 0x004F7170 (FUN_004F7170)
 *
 * What it does:
 * Appends one frame-managed registry slot and links it to `ownerHeadLink`.
 */
void moho::WWinManagedFrame::AppendManagedSlotForOwner(
  ManagedWindowSlot** const ownerHeadLink
)
{
  AppendManagedSlot<WWinManagedFrame>(managedFrames, ownerHeadLink);
}

/**
 * Address: 0x004F40E0 (FUN_004F40E0, WWinManagedFrame ctor tail)
 *
 * What it does:
 * Registers this frame owner head in the global managed-frame slot registry.
 */
void moho::WWinManagedFrame::RegisterManagedOwnerSlot()
{
  RegisterManagedOwnerSlotImpl<WWinManagedFrame>(managedFrames, &mManagedSlotsHead);
}

/**
 * Address: 0x004F4230 (FUN_004F4230, WWinManagedFrame dtor core)
 *
 * What it does:
 * Unlinks and clears every managed slot currently chained to this frame.
 */
void moho::WWinManagedFrame::ReleaseManagedOwnerSlots()
{
  ReleaseManagedOwnerSlotChain(mManagedSlotsHead);
}

void moho::WWinManagedFrame::DestroyManagedOwners(
  msvc8::vector<ManagedWindowSlot>& slots
)
{
  DestroyManagedRuntimeCollection<WWinManagedFrame>(slots);
}

/**
 * Address: 0x00453AA0 (FUN_00453AA0, sub_453AA0)
 *
 * IDA signature:
 * void __thiscall sub_453AA0(_DWORD *this);
 *
 * What it does:
 * Resets the viewport render-state dword at `+0x0C` to `-1`. Called
 * from the render-camera-outline path as the viewport begins a new
 * render pass.
 */
namespace
{
  struct WRenViewportRenderView final
  {
    std::uint8_t mUnknown0000_215B[0x215C];
    std::uint8_t mDebugCanvas[0x40];
    moho::GeomCamera3* mCam; // +0x219C
    std::uint8_t mUnknown21A0_2C7[0x128];
    struct PrimBatcherView final
    {
      moho::CD3DPrimBatcher* batcher;
    };
    PrimBatcherView mPrimBatcher; // +0x2C8
    std::uint8_t mUnknown2CC_307[0x3C];
    Wm3::Vector2i mScreenPos; // +0x308
    Wm3::Vector2i mScreenSize; // +0x310
    std::uint8_t mUnknown318_31F[0x08];
    std::int32_t mHead; // +0x320
    std::uint8_t mUnknown324_4EF[0x1CC];
    struct ShadowView final
    {
      std::uint8_t mUnknown00_07[0x08];
      std::int32_t shadow_Fidelity; // +0x08
    };
    ShadowView mShadowRenderer; // +0x4F0
  };

  static_assert(
    offsetof(WRenViewportRenderView, mDebugCanvas) == 0x215C,
    "WRenViewportRenderView::mDebugCanvas offset must be 0x215C"
  );
  static_assert(
    offsetof(WRenViewportRenderView, mCam) == 0x219C, "WRenViewportRenderView::mCam offset must be 0x219C"
  );
  [[nodiscard]] WRenViewportRenderView* AsRenderView(moho::WRenViewport* const viewport) noexcept
  {
    return reinterpret_cast<WRenViewportRenderView*>(viewport);
  }
} // namespace

namespace moho
{
  extern bool ren_ShowSkeletons;
} // namespace moho

void moho::WRenViewport::ResetRenderState0C() noexcept
{
  mRenderState0C = -1;
}

/**
 * Address: 0x007F8290 (FUN_007F8290, Moho::WRenViewport::RenderMeshes)
 *
 * What it does:
 * Sets the render target, viewport, and color-write state for one viewport
 * mesh pass, then dispatches either skeleton-debug rendering or the normal
 * mesh batch renderer depending on `ren_ShowSkeletons`.
 */
void moho::WRenViewport::RenderMeshes(const int meshFlags, const bool mirrored)
{
  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::GeomCamera3* const cam = runtime->mCam;
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(runtime->mHead, false, 0, 1.0f, 0);
  moho::D3D_GetDevice()->SetViewport(&runtime->mScreenPos, &runtime->mScreenSize, 0.0f, 1.0f);
  device->SetColorWriteState(true, true);

  moho::Shadow* const shadowRenderer = runtime->mShadowRenderer.shadow_Fidelity != 0
    ? reinterpret_cast<moho::Shadow*>(&runtime->mShadowRenderer)
    : nullptr;

  moho::MeshRenderer* const instance = moho::MeshRenderer::GetInstance();
  if (moho::ren_ShowSkeletons) {
    instance->RenderSkeletons(
      reinterpret_cast<moho::CD3DPrimBatcher*>(runtime->mPrimBatcher.batcher),
      reinterpret_cast<moho::CDebugCanvas*>(runtime->mDebugCanvas),
      *cam,
      true
    );
    return;
  }

  instance->Render(meshFlags, *cam, shadowRenderer, instance->meshes);
  (void)mirrored;
}
