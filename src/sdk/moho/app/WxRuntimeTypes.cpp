#include "WxRuntimeTypes.h"

#include <Windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <fcntl.h>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <system_error>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <io.h>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "libpng/PngReadRuntime.h"
#include "moho/console/CConCommand.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/SimDriver.h"
#include "moho/terrain/TerrainFactory.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/ui/IUIManager.h"

extern "C" void __cdecl _free_crt(void* ptr);

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

  class WxPngIoStreamRuntime
  {
  public:
    virtual ~WxPngIoStreamRuntime() = default;
    virtual void RuntimeSlot08() = 0;
    virtual void RuntimeSlot0C() = 0;
    virtual void WritePngBytes(png_bytep bytes, png_size_t byteCount) = 0;
    virtual void ReadPngBytes(png_bytep bytes, png_size_t byteCount) = 0;
  };

  struct WxPngIoContextRuntime
  {
    std::uint8_t setJmpAndStateLane[0x44]{};
    WxPngIoStreamRuntime* stream = nullptr;
  };
  static_assert(offsetof(WxPngIoContextRuntime, stream) == 0x44, "WxPngIoContextRuntime::stream offset must be 0x44");

  /**
   * Address: 0x00974E30 (FUN_00974E30, write_data_fn)
   *
   * What it does:
   * Resolves the active wx/libpng callback context and forwards one PNG input
   * byte-span request into the stream read lane.
   */
  void wxPngReadFromStreamCallback(
    png_structp const pngPtr,
    png_bytep const bytes,
    png_size_t const byteCount
  )
  {
    auto* const ioContext = static_cast<WxPngIoContextRuntime*>(png_get_io_ptr(pngPtr));
    ioContext->stream->ReadPngBytes(bytes, byteCount);
  }

  /**
   * Address: 0x00974E60 (FUN_00974E60, _PNG_stream_writer)
   *
   * What it does:
   * Resolves the active wx/libpng callback context and forwards one PNG output
   * byte-span request into the stream write lane.
   */
  void wxPngWriteToStreamCallback(
    png_structp const pngPtr,
    png_bytep const bytes,
    png_size_t const byteCount
  )
  {
    auto* const ioContext = static_cast<WxPngIoContextRuntime*>(png_get_io_ptr(pngPtr));
    ioContext->stream->WritePngBytes(bytes, byteCount);
  }

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
  int gWxColourDisplayCache = -1;
  HCURSOR gs_wxBusyCursor = nullptr;
  HCURSOR gs_wxBusyCursorOld = nullptr;
  int gs_wxBusyCursorCount = 0;

  class WxStockListRuntimeBase
  {
  public:
    virtual ~WxStockListRuntimeBase() = default;
  };

  WxStockListRuntimeBase* wxTheBrushList = nullptr;
  WxStockListRuntimeBase* wxThePenList = nullptr;
  WxStockListRuntimeBase* wxTheFontList = nullptr;
  WxStockListRuntimeBase* wxTheBitmapList = nullptr;

  void DeleteStockList(WxStockListRuntimeBase*& stockList) noexcept
  {
    delete stockList;
    stockList = nullptr;
  }

  /**
   * Address: 0x00A19150 (FUN_00A19150)
   *
   * What it does:
   * Scans one runtime IID pointer list and reports whether any entry matches
   * the requested COM interface id.
   */
  [[nodiscard]] bool IsIidFromList(
    REFIID iid,
    const IID* const* const iidList,
    const unsigned int count
  )
  {
    if (count == 0U) {
      return false;
    }

    for (unsigned int index = 0U; index < count; ++index) {
      if (InlineIsEqualGUID(iid, *iidList[index])) {
        return true;
      }
    }

    return false;
  }

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

  [[nodiscard]] std::wstring ToLowerWide(
    std::wstring value
  )
  {
    std::transform(
      value.begin(),
      value.end(),
      value.begin(),
      [](const wchar_t ch) {
      return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(ch)));
    }
    );
    return value;
  }

  [[nodiscard]] bool ContainsNoCase(
    const std::wstring& haystack,
    const wchar_t* const needle
  )
  {
    if (needle == nullptr || *needle == L'\0') {
      return false;
    }

    const std::wstring lowerHaystack = ToLowerWide(haystack);
    const std::wstring lowerNeedle = ToLowerWide(std::wstring(needle));
    return lowerHaystack.find(lowerNeedle) != std::wstring::npos;
  }

  [[nodiscard]] bool TryParseIntToken(
    const std::wstring& token,
    std::int32_t* const outValue
  )
  {
    if (token.empty() || outValue == nullptr) {
      return false;
    }

    std::size_t parsedCount = 0;
    const long value = std::wcstol(token.c_str(), nullptr, 10);
    if (value == 0L && token[0] != L'0') {
      return false;
    }

    const std::wstring normalized = (token[0] == L'+' || token[0] == L'-') ? token.substr(1) : token;
    for (const wchar_t ch : normalized) {
      if (ch < L'0' || ch > L'9') {
        return false;
      }
      ++parsedCount;
    }
    if (parsedCount == 0) {
      return false;
    }

    *outValue = static_cast<std::int32_t>(value);
    return true;
  }

  [[nodiscard]] bool TryMapEncodingToCharset(
    const std::wstring& token,
    std::int32_t* const outCharset
  )
  {
    if (outCharset == nullptr) {
      return false;
    }

    const std::wstring lower = ToLowerWide(token);
    if (lower == L"ansi" || lower == L"cp1252" || lower == L"latin1" || lower == L"iso8859-1") {
      *outCharset = 0;
      return true;
    }
    if (lower == L"cp1250" || lower == L"easteurope" || lower == L"iso8859-2") {
      *outCharset = 238;
      return true;
    }
    if (lower == L"cp1251" || lower == L"russian" || lower == L"koi8-r") {
      *outCharset = 204;
      return true;
    }
    if (lower == L"cp1253" || lower == L"greek") {
      *outCharset = 161;
      return true;
    }
    if (lower == L"cp1254" || lower == L"turkish") {
      *outCharset = 162;
      return true;
    }
    if (lower == L"cp1255" || lower == L"hebrew") {
      *outCharset = 177;
      return true;
    }
    if (lower == L"cp1256" || lower == L"arabic") {
      *outCharset = 178;
      return true;
    }
    if (lower == L"cp1257" || lower == L"baltic") {
      *outCharset = 186;
      return true;
    }
    if (lower == L"cp1258" || lower == L"vietnamese") {
      *outCharset = 163;
      return true;
    }
    if (lower == L"utf-8" || lower == L"utf8" || lower == L"default") {
      *outCharset = 1;
      return true;
    }

    return false;
  }

  [[nodiscard]] std::vector<std::wstring> SplitNativeFontDescriptionTokens(
    const std::wstring& description
  )
  {
    std::vector<std::wstring> tokens{};
    std::wstring token{};

    auto flushToken = [&]() {
      if (!token.empty()) {
        tokens.push_back(token);
        token.clear();
      }
    };

    for (const wchar_t ch : description) {
      const bool isSeparator = ch == L';' || ch == L',' || std::iswspace(static_cast<wint_t>(ch)) != 0;
      if (isSeparator) {
        flushToken();
      } else {
        token.push_back(ch);
      }
    }
    flushToken();
    return tokens;
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

  struct WxLogFrameRuntimeState
  {
    std::wstring title{};
    std::wstring windowName{};
    std::wstring statusText{};
    wxTextCtrlRuntime* textControl = nullptr;
    wxLogWindowRuntime* ownerLogWindow = nullptr;
    std::array<std::int32_t, 3> logMenuItemIds{{5003, 5033, 5001}};
    bool menuReady = false;
  };

  std::unordered_map<const wxTopLevelWindowRuntime*, WxTopLevelWindowRuntimeState>
    gWxTopLevelWindowRuntimeStateByWindow{};
  std::unordered_map<const wxDialogRuntime*, WxDialogRuntimeState> gWxDialogRuntimeStateByDialog{};
  std::unordered_map<const wxLogFrameRuntime*, WxLogFrameRuntimeState> gWxLogFrameRuntimeStateByFrame{};

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
  std::int32_t gWxEvtUpdateUiRuntimeType = 0;
  std::int32_t gWxEvtSizeRuntimeType = 0;
  std::int32_t gWxEvtPaintRuntimeType = 0;
  std::int32_t gWxEvtNcPaintRuntimeType = 0;
  std::int32_t gWxEvtEraseBackgroundRuntimeType = 0;
  std::int32_t gWxEvtMoveRuntimeType = 0;
  std::int32_t gWxEvtActivateRuntimeType = 0;
  std::int32_t gWxEvtInitDialogRuntimeType = 0;
  std::int32_t gWxEvtSysColourChangedRuntimeType = 0;
  std::int32_t gWxEvtDisplayChangedRuntimeType = 0;
  std::int32_t gWxEvtNavigationKeyRuntimeType = 0;
  std::int32_t gWxEvtPaletteChangedRuntimeType = 0;
  std::int32_t gWxEvtQueryNewPaletteRuntimeType = 0;
  std::int32_t gWxEvtShowRuntimeType = 0;
  std::int32_t gWxEvtMaximizeRuntimeType = 0;
  std::int32_t gWxEvtIconizeRuntimeType = 0;
  std::int32_t gWxEvtChildFocusRuntimeType = 0;
  std::int32_t gWxEvtWindowCreateRuntimeType = 0;
  std::int32_t gWxEvtWindowDestroyRuntimeType = 0;
  std::int32_t gWxEvtSetCursorRuntimeType = 0;

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

  [[nodiscard]] std::int32_t EnsureWxEvtUpdateUiRuntimeType()
  {
    if (gWxEvtUpdateUiRuntimeType == 0) {
      gWxEvtUpdateUiRuntimeType = wxNewEventType();
    }
    return gWxEvtUpdateUiRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtSizeRuntimeType()
  {
    if (gWxEvtSizeRuntimeType == 0) {
      gWxEvtSizeRuntimeType = wxNewEventType();
    }
    return gWxEvtSizeRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtPaintRuntimeType()
  {
    if (gWxEvtPaintRuntimeType == 0) {
      gWxEvtPaintRuntimeType = wxNewEventType();
    }
    return gWxEvtPaintRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtNcPaintRuntimeType()
  {
    if (gWxEvtNcPaintRuntimeType == 0) {
      gWxEvtNcPaintRuntimeType = wxNewEventType();
    }
    return gWxEvtNcPaintRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtEraseBackgroundRuntimeType()
  {
    if (gWxEvtEraseBackgroundRuntimeType == 0) {
      gWxEvtEraseBackgroundRuntimeType = wxNewEventType();
    }
    return gWxEvtEraseBackgroundRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtMoveRuntimeType()
  {
    if (gWxEvtMoveRuntimeType == 0) {
      gWxEvtMoveRuntimeType = wxNewEventType();
    }
    return gWxEvtMoveRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtActivateRuntimeType()
  {
    if (gWxEvtActivateRuntimeType == 0) {
      gWxEvtActivateRuntimeType = wxNewEventType();
    }
    return gWxEvtActivateRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtInitDialogRuntimeType()
  {
    if (gWxEvtInitDialogRuntimeType == 0) {
      gWxEvtInitDialogRuntimeType = wxNewEventType();
    }
    return gWxEvtInitDialogRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtSysColourChangedRuntimeType()
  {
    if (gWxEvtSysColourChangedRuntimeType == 0) {
      gWxEvtSysColourChangedRuntimeType = wxNewEventType();
    }
    return gWxEvtSysColourChangedRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtDisplayChangedRuntimeType()
  {
    if (gWxEvtDisplayChangedRuntimeType == 0) {
      gWxEvtDisplayChangedRuntimeType = wxNewEventType();
    }
    return gWxEvtDisplayChangedRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtNavigationKeyRuntimeType()
  {
    if (gWxEvtNavigationKeyRuntimeType == 0) {
      gWxEvtNavigationKeyRuntimeType = wxNewEventType();
    }
    return gWxEvtNavigationKeyRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtPaletteChangedRuntimeType()
  {
    if (gWxEvtPaletteChangedRuntimeType == 0) {
      gWxEvtPaletteChangedRuntimeType = wxNewEventType();
    }
    return gWxEvtPaletteChangedRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtQueryNewPaletteRuntimeType()
  {
    if (gWxEvtQueryNewPaletteRuntimeType == 0) {
      gWxEvtQueryNewPaletteRuntimeType = wxNewEventType();
    }
    return gWxEvtQueryNewPaletteRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtShowRuntimeType()
  {
    if (gWxEvtShowRuntimeType == 0) {
      gWxEvtShowRuntimeType = wxNewEventType();
    }
    return gWxEvtShowRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtMaximizeRuntimeType()
  {
    if (gWxEvtMaximizeRuntimeType == 0) {
      gWxEvtMaximizeRuntimeType = wxNewEventType();
    }
    return gWxEvtMaximizeRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtIconizeRuntimeType()
  {
    if (gWxEvtIconizeRuntimeType == 0) {
      gWxEvtIconizeRuntimeType = wxNewEventType();
    }
    return gWxEvtIconizeRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtChildFocusRuntimeType()
  {
    if (gWxEvtChildFocusRuntimeType == 0) {
      gWxEvtChildFocusRuntimeType = wxNewEventType();
    }
    return gWxEvtChildFocusRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtWindowCreateRuntimeType()
  {
    if (gWxEvtWindowCreateRuntimeType == 0) {
      gWxEvtWindowCreateRuntimeType = wxNewEventType();
    }
    return gWxEvtWindowCreateRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtWindowDestroyRuntimeType()
  {
    if (gWxEvtWindowDestroyRuntimeType == 0) {
      gWxEvtWindowDestroyRuntimeType = wxNewEventType();
    }
    return gWxEvtWindowDestroyRuntimeType;
  }

  [[nodiscard]] std::int32_t EnsureWxEvtSetCursorRuntimeType()
  {
    if (gWxEvtSetCursorRuntimeType == 0) {
      gWxEvtSetCursorRuntimeType = wxNewEventType();
    }
    return gWxEvtSetCursorRuntimeType;
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

  class WxSizeEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxSizeEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtSizeRuntimeType())
      , mSizeX(0)
      , mSizeY(0)
    {}

    WxSizeEventFactoryRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxSizeEventFactoryRuntime();
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
      clone->mSizeX = mSizeX;
      clone->mSizeY = mSizeY;
      return clone;
    }

    std::int32_t mSizeX = 0;
    std::int32_t mSizeY = 0;
  };

  static_assert(
    offsetof(WxSizeEventFactoryRuntime, mSizeX) == 0x20,
    "WxSizeEventFactoryRuntime::mSizeX offset must be 0x20"
  );
  static_assert(
    offsetof(WxSizeEventFactoryRuntime, mSizeY) == 0x24,
    "WxSizeEventFactoryRuntime::mSizeY offset must be 0x24"
  );
  static_assert(sizeof(WxSizeEventFactoryRuntime) == 0x28, "WxSizeEventFactoryRuntime size must be 0x28");

  class WxPaintEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxPaintEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtPaintRuntimeType())
    {}

    WxPaintEventFactoryRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxPaintEventFactoryRuntime();
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
      return clone;
    }
  };

  static_assert(sizeof(WxPaintEventFactoryRuntime) == 0x20, "WxPaintEventFactoryRuntime size must be 0x20");

  class WxNcPaintEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxNcPaintEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtNcPaintRuntimeType())
    {}

    WxNcPaintEventFactoryRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxNcPaintEventFactoryRuntime();
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
      return clone;
    }
  };

  static_assert(sizeof(WxNcPaintEventFactoryRuntime) == 0x20, "WxNcPaintEventFactoryRuntime size must be 0x20");

  class WxEraseEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxEraseEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtEraseBackgroundRuntimeType())
      , mDeviceContext(nullptr)
    {}

    WxEraseEventFactoryRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxEraseEventFactoryRuntime();
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
      clone->mDeviceContext = mDeviceContext;
      return clone;
    }

    void* mDeviceContext = nullptr;
  };

  static_assert(
    offsetof(WxEraseEventFactoryRuntime, mDeviceContext) == 0x20,
    "WxEraseEventFactoryRuntime::mDeviceContext offset must be 0x20"
  );
  static_assert(sizeof(WxEraseEventFactoryRuntime) == 0x24, "WxEraseEventFactoryRuntime size must be 0x24");

  class WxMoveEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxMoveEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtMoveRuntimeType())
      , mX(0)
      , mY(0)
    {}

    WxMoveEventFactoryRuntime* Clone() const override
    {
      auto* const clone = new (std::nothrow) WxMoveEventFactoryRuntime();
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
      clone->mX = mX;
      clone->mY = mY;
      return clone;
    }

    std::int32_t mX = 0;
    std::int32_t mY = 0;
  };

  static_assert(
    offsetof(WxMoveEventFactoryRuntime, mX) == 0x20,
    "WxMoveEventFactoryRuntime::mX offset must be 0x20"
  );
  static_assert(
    offsetof(WxMoveEventFactoryRuntime, mY) == 0x24,
    "WxMoveEventFactoryRuntime::mY offset must be 0x24"
  );
  static_assert(sizeof(WxMoveEventFactoryRuntime) == 0x28, "WxMoveEventFactoryRuntime size must be 0x28");

  class WxFocusEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxFocusEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mFocusedWindow(nullptr)
    {}

    WxFocusEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxFocusEventFactoryRuntime(*this);
    }

    wxWindowBase* mFocusedWindow = nullptr;
  };

  static_assert(
    offsetof(WxFocusEventFactoryRuntime, mFocusedWindow) == 0x20,
    "WxFocusEventFactoryRuntime::mFocusedWindow offset must be 0x20"
  );
  static_assert(sizeof(WxFocusEventFactoryRuntime) == 0x24, "WxFocusEventFactoryRuntime size must be 0x24");

  class WxCloseEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxCloseEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mCanVeto(1)
      , mVeto(0)
      , mLoggingOff(1)
      , mReserved23(0)
    {}

    WxCloseEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxCloseEventFactoryRuntime(*this);
    }

    std::uint8_t mCanVeto = 1;
    std::uint8_t mVeto = 0;
    std::uint8_t mLoggingOff = 1;
    std::uint8_t mReserved23 = 0;
  };

  static_assert(offsetof(WxCloseEventFactoryRuntime, mCanVeto) == 0x20, "WxCloseEventFactoryRuntime::mCanVeto offset must be 0x20");
  static_assert(offsetof(WxCloseEventFactoryRuntime, mVeto) == 0x21, "WxCloseEventFactoryRuntime::mVeto offset must be 0x21");
  static_assert(
    offsetof(WxCloseEventFactoryRuntime, mLoggingOff) == 0x22,
    "WxCloseEventFactoryRuntime::mLoggingOff offset must be 0x22"
  );
  static_assert(sizeof(WxCloseEventFactoryRuntime) == 0x24, "WxCloseEventFactoryRuntime size must be 0x24");

  class WxShowEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxShowEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtShowRuntimeType())
      , mShown(0)
      , mPadding21To23{0, 0, 0}
    {}

    WxShowEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxShowEventFactoryRuntime(*this);
    }

    std::uint8_t mShown = 0;
    std::uint8_t mPadding21To23[3] = {0, 0, 0};
  };

  static_assert(offsetof(WxShowEventFactoryRuntime, mShown) == 0x20, "WxShowEventFactoryRuntime::mShown offset must be 0x20");
  static_assert(sizeof(WxShowEventFactoryRuntime) == 0x24, "WxShowEventFactoryRuntime size must be 0x24");

  class WxMaximizeEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxMaximizeEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtMaximizeRuntimeType())
    {}

    WxMaximizeEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxMaximizeEventFactoryRuntime(*this);
    }
  };

  static_assert(sizeof(WxMaximizeEventFactoryRuntime) == 0x20, "WxMaximizeEventFactoryRuntime size must be 0x20");

  class WxIconizeEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxIconizeEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtIconizeRuntimeType())
      , mIconized(1)
      , mPadding21To23{0, 0, 0}
    {}

    WxIconizeEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxIconizeEventFactoryRuntime(*this);
    }

    std::uint8_t mIconized = 1;
    std::uint8_t mPadding21To23[3] = {0, 0, 0};
  };

  static_assert(offsetof(WxIconizeEventFactoryRuntime, mIconized) == 0x20, "WxIconizeEventFactoryRuntime::mIconized offset must be 0x20");
  static_assert(sizeof(WxIconizeEventFactoryRuntime) == 0x24, "WxIconizeEventFactoryRuntime size must be 0x24");

  class WxActivateEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxActivateEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtActivateRuntimeType())
      , mIsActive(1)
      , mPadding21To23{0, 0, 0}
    {}

    WxActivateEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxActivateEventFactoryRuntime(*this);
    }

    std::uint8_t mIsActive = 1;
    std::uint8_t mPadding21To23[3] = {0, 0, 0};
  };

  static_assert(
    offsetof(WxActivateEventFactoryRuntime, mIsActive) == 0x20,
    "WxActivateEventFactoryRuntime::mIsActive offset must be 0x20"
  );
  static_assert(sizeof(WxActivateEventFactoryRuntime) == 0x24, "WxActivateEventFactoryRuntime size must be 0x24");

  class WxInitDialogEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxInitDialogEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtInitDialogRuntimeType())
    {}

    WxInitDialogEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxInitDialogEventFactoryRuntime(*this);
    }
  };

  static_assert(sizeof(WxInitDialogEventFactoryRuntime) == 0x20, "WxInitDialogEventFactoryRuntime size must be 0x20");

  class WxSysColourChangedEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxSysColourChangedEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtSysColourChangedRuntimeType())
    {}

    WxSysColourChangedEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxSysColourChangedEventFactoryRuntime(*this);
    }
  };

  static_assert(
    sizeof(WxSysColourChangedEventFactoryRuntime) == 0x20,
    "WxSysColourChangedEventFactoryRuntime size must be 0x20"
  );

  class WxDisplayChangedEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxDisplayChangedEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtDisplayChangedRuntimeType())
    {}

    WxDisplayChangedEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxDisplayChangedEventFactoryRuntime(*this);
    }
  };

  static_assert(sizeof(WxDisplayChangedEventFactoryRuntime) == 0x20, "WxDisplayChangedEventFactoryRuntime size must be 0x20");

  class WxNavigationKeyEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxNavigationKeyEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtNavigationKeyRuntimeType())
      , mNavigationFlags(5)
      , mCurrentFocusWindow(nullptr)
    {}

    WxNavigationKeyEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxNavigationKeyEventFactoryRuntime(*this);
    }

    std::int32_t mNavigationFlags = 5;
    wxWindowBase* mCurrentFocusWindow = nullptr;
  };

  static_assert(
    offsetof(WxNavigationKeyEventFactoryRuntime, mNavigationFlags) == 0x20,
    "WxNavigationKeyEventFactoryRuntime::mNavigationFlags offset must be 0x20"
  );
  static_assert(
    offsetof(WxNavigationKeyEventFactoryRuntime, mCurrentFocusWindow) == 0x24,
    "WxNavigationKeyEventFactoryRuntime::mCurrentFocusWindow offset must be 0x24"
  );
  static_assert(
    sizeof(WxNavigationKeyEventFactoryRuntime) == 0x28,
    "WxNavigationKeyEventFactoryRuntime size must be 0x28"
  );

  class WxPaletteChangedEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxPaletteChangedEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtPaletteChangedRuntimeType())
      , mChangedWindow(nullptr)
    {}

    WxPaletteChangedEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxPaletteChangedEventFactoryRuntime(*this);
    }

    wxWindowBase* mChangedWindow = nullptr;
  };

  static_assert(
    offsetof(WxPaletteChangedEventFactoryRuntime, mChangedWindow) == 0x20,
    "WxPaletteChangedEventFactoryRuntime::mChangedWindow offset must be 0x20"
  );
  static_assert(
    sizeof(WxPaletteChangedEventFactoryRuntime) == 0x24,
    "WxPaletteChangedEventFactoryRuntime size must be 0x24"
  );

  class WxQueryNewPaletteEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxQueryNewPaletteEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtQueryNewPaletteRuntimeType())
      , mPaletteRealized(0)
      , mPadding21To23{0, 0, 0}
    {}

    WxQueryNewPaletteEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxQueryNewPaletteEventFactoryRuntime(*this);
    }

    std::uint8_t mPaletteRealized = 0;
    std::uint8_t mPadding21To23[3] = {0, 0, 0};
  };

  static_assert(
    offsetof(WxQueryNewPaletteEventFactoryRuntime, mPaletteRealized) == 0x20,
    "WxQueryNewPaletteEventFactoryRuntime::mPaletteRealized offset must be 0x20"
  );
  static_assert(
    sizeof(WxQueryNewPaletteEventFactoryRuntime) == 0x24,
    "WxQueryNewPaletteEventFactoryRuntime size must be 0x24"
  );

  class WxMenuEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxMenuEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mMenuId(0)
    {}

    WxMenuEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxMenuEventFactoryRuntime(*this);
    }

    std::int32_t mMenuId = 0;
  };

  static_assert(offsetof(WxMenuEventFactoryRuntime, mMenuId) == 0x20, "WxMenuEventFactoryRuntime::mMenuId offset must be 0x20");
  static_assert(sizeof(WxMenuEventFactoryRuntime) == 0x24, "WxMenuEventFactoryRuntime size must be 0x24");

  class WxJoystickEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxJoystickEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mPositionX(0)
      , mPositionY(0)
      , mPositionZ(0)
      , mButtonChange(0)
      , mButtonState(0)
      , mJoystickIndex(0)
    {}

    WxJoystickEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxJoystickEventFactoryRuntime(*this);
    }

    std::int32_t mPositionX = 0;
    std::int32_t mPositionY = 0;
    std::int32_t mPositionZ = 0;
    std::int32_t mButtonChange = 0;
    std::int32_t mButtonState = 0;
    std::int32_t mJoystickIndex = 0;
  };

  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mPositionX) == 0x20,
    "WxJoystickEventFactoryRuntime::mPositionX offset must be 0x20"
  );
  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mPositionY) == 0x24,
    "WxJoystickEventFactoryRuntime::mPositionY offset must be 0x24"
  );
  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mPositionZ) == 0x28,
    "WxJoystickEventFactoryRuntime::mPositionZ offset must be 0x28"
  );
  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mButtonChange) == 0x2C,
    "WxJoystickEventFactoryRuntime::mButtonChange offset must be 0x2C"
  );
  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mButtonState) == 0x30,
    "WxJoystickEventFactoryRuntime::mButtonState offset must be 0x30"
  );
  static_assert(
    offsetof(WxJoystickEventFactoryRuntime, mJoystickIndex) == 0x34,
    "WxJoystickEventFactoryRuntime::mJoystickIndex offset must be 0x34"
  );
  static_assert(sizeof(WxJoystickEventFactoryRuntime) == 0x38, "WxJoystickEventFactoryRuntime size must be 0x38");

  class WxScrollEventFactoryRuntime final : public wxCommandEventRuntime
  {
  public:
    WxScrollEventFactoryRuntime()
      : wxCommandEventRuntime(0, 0)
    {}

    WxScrollEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxScrollEventFactoryRuntime(*this);
    }
  };

  static_assert(sizeof(WxScrollEventFactoryRuntime) == 0x34, "WxScrollEventFactoryRuntime size must be 0x34");

  class WxContextMenuEventRuntime final : public wxCommandEventRuntime
  {
  public:
    WxContextMenuEventRuntime()
      : wxCommandEventRuntime(0, 0)
      , mContextMenuPosition{-1, -1}
    {}

    WxContextMenuEventRuntime* Clone() const override
    {
      return new (std::nothrow) WxContextMenuEventRuntime(*this);
    }

    wxPoint mContextMenuPosition{};
  };

  static_assert(
    offsetof(WxContextMenuEventRuntime, mContextMenuPosition) == 0x34,
    "WxContextMenuEventRuntime::mContextMenuPosition offset must be 0x34"
  );
  static_assert(
    sizeof(WxContextMenuEventRuntime) == 0x3C,
    "WxContextMenuEventRuntime size must be 0x3C"
  );

  class WxNotifyEventRuntime final : public wxCommandEventRuntime
  {
  public:
    WxNotifyEventRuntime()
      : wxCommandEventRuntime(0, 0)
      , mAllow(true)
      , mPadding35To37{0, 0, 0}
    {}

    WxNotifyEventRuntime* Clone() const override
    {
      return new (std::nothrow) WxNotifyEventRuntime(*this);
    }

    std::uint8_t mAllow = 1;
    std::uint8_t mPadding35To37[3] = {0, 0, 0};
  };

  static_assert(
    offsetof(WxNotifyEventRuntime, mAllow) == 0x34,
    "WxNotifyEventRuntime::mAllow offset must be 0x34"
  );
  static_assert(sizeof(WxNotifyEventRuntime) == 0x38, "WxNotifyEventRuntime size must be 0x38");

  class WxUpdateUIEventRuntime final : public wxCommandEventRuntime
  {
  public:
    WxUpdateUIEventRuntime()
      : wxCommandEventRuntime(EnsureWxEvtUpdateUiRuntimeType(), 0)
      , mSetChecked(0)
      , mSetEnabled(0)
      , mSetShown(0)
      , mSetText(0)
      , mSetTextColour(0)
      , mPadding39To3B{0, 0, 0}
      , mTextLabel(L"")
    {}

    WxUpdateUIEventRuntime* Clone() const override
    {
      return new (std::nothrow) WxUpdateUIEventRuntime(*this);
    }

    std::uint8_t mSetChecked = 0;
    std::uint8_t mSetEnabled = 0;
    std::uint8_t mSetShown = 0;
    std::uint8_t mSetText = 0;
    std::uint8_t mSetTextColour = 0;
    std::uint8_t mPadding39To3B[3] = {0, 0, 0};
    const wchar_t* mTextLabel = L"";
  };

  static_assert(
    offsetof(WxUpdateUIEventRuntime, mSetChecked) == 0x34,
    "WxUpdateUIEventRuntime::mSetChecked offset must be 0x34"
  );
  static_assert(
    offsetof(WxUpdateUIEventRuntime, mTextLabel) == 0x3C,
    "WxUpdateUIEventRuntime::mTextLabel offset must be 0x3C"
  );
  static_assert(sizeof(WxUpdateUIEventRuntime) == 0x40, "WxUpdateUIEventRuntime size must be 0x40");

  class WxEvtHandlerFactoryRuntime
  {
  public:
    virtual ~WxEvtHandlerFactoryRuntime() = default;

    void* mRefData = nullptr;                            // +0x04
    WxEvtHandlerFactoryRuntime* mNextHandler = nullptr; // +0x08
    WxEvtHandlerFactoryRuntime* mPreviousHandler = nullptr; // +0x0C
    std::uint8_t mEnabled = 1;                          // +0x10
    std::uint8_t mPadding11To13[3] = {0, 0, 0};        // +0x11
    void* mDynamicEvents = nullptr;                     // +0x14
    std::uint8_t mIsWindow = 0;                         // +0x18
    std::uint8_t mPadding19To1B[3] = {0, 0, 0};        // +0x19
    void* mPendingEvents = nullptr;                     // +0x1C
    void* mEventsLocker = nullptr;                      // +0x20
    std::uint32_t mClientDataType = 0;                  // +0x24
  };
  static_assert(sizeof(WxEvtHandlerFactoryRuntime) == 0x28, "WxEvtHandlerFactoryRuntime size must be 0x28");

  class WxScrollWinEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxScrollWinEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mCommandInt(0)
      , mExtraLong(0)
    {}

    WxScrollWinEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxScrollWinEventFactoryRuntime(*this);
    }

    std::int32_t mCommandInt = 0;
    std::int32_t mExtraLong = 0;
  };
  static_assert(sizeof(WxScrollWinEventFactoryRuntime) == 0x28, "WxScrollWinEventFactoryRuntime size must be 0x28");

  class WxMouseEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxMouseEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mMetaDown(0)
      , mAltDown(0)
      , mControlDown(0)
      , mShiftDown(0)
      , mLeftDown(0)
      , mRightDown(0)
      , mMiddleDown(0)
      , mReserved27(0)
      , mX(0)
      , mY(0)
      , mWheelRotation(0)
      , mWheelDelta(0)
      , mLinesPerAction(0)
    {}

    WxMouseEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxMouseEventFactoryRuntime(*this);
    }

    std::uint8_t mMetaDown = 0;
    std::uint8_t mAltDown = 0;
    std::uint8_t mControlDown = 0;
    std::uint8_t mShiftDown = 0;
    std::uint8_t mLeftDown = 0;
    std::uint8_t mRightDown = 0;
    std::uint8_t mMiddleDown = 0;
    std::uint8_t mReserved27 = 0;
    std::int32_t mX = 0;
    std::int32_t mY = 0;
    std::int32_t mWheelRotation = 0;
    std::int32_t mWheelDelta = 0;
    std::int32_t mLinesPerAction = 0;
  };
  static_assert(sizeof(WxMouseEventFactoryRuntime) == 0x3C, "WxMouseEventFactoryRuntime size must be 0x3C");

  class WxKeyEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxKeyEventFactoryRuntime()
      : wxEventRuntime(0, 0)
      , mShiftDown(0)
      , mControlDown(0)
      , mMetaDown(0)
      , mAltDown(0)
      , mKeyCode(0)
      , mScanCode(0)
      , mUniChar(0)
      , mUnknown30To3B{0, 0, 0}
    {}

    WxKeyEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxKeyEventFactoryRuntime(*this);
    }

    std::uint8_t mShiftDown = 0;
    std::uint8_t mControlDown = 0;
    std::uint8_t mMetaDown = 0;
    std::uint8_t mAltDown = 0;
    std::int32_t mKeyCode = 0;
    std::int32_t mScanCode = 0;
    std::int32_t mUniChar = 0;
    std::int32_t mUnknown30To3B[3] = {0, 0, 0};
  };
  static_assert(sizeof(WxKeyEventFactoryRuntime) == 0x3C, "WxKeyEventFactoryRuntime size must be 0x3C");

  class WxChildFocusEventFactoryRuntime final : public wxCommandEventRuntime
  {
  public:
    WxChildFocusEventFactoryRuntime()
      : wxCommandEventRuntime(EnsureWxEvtChildFocusRuntimeType(), 0)
    {
      mEventObject = nullptr;
    }

    WxChildFocusEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxChildFocusEventFactoryRuntime(*this);
    }
  };
  static_assert(sizeof(WxChildFocusEventFactoryRuntime) == 0x34, "WxChildFocusEventFactoryRuntime size must be 0x34");

  class WxSetCursorEventFactoryRuntime final : public wxEventRuntime
  {
  public:
    WxSetCursorEventFactoryRuntime()
      : wxEventRuntime(0, EnsureWxEvtSetCursorRuntimeType())
      , mX(0)
      , mY(0)
      , mCursorStorage{0, 0, 0}
    {}

    WxSetCursorEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxSetCursorEventFactoryRuntime(*this);
    }

    std::int32_t mX = 0;
    std::int32_t mY = 0;
    std::int32_t mCursorStorage[3] = {0, 0, 0};
  };
  static_assert(sizeof(WxSetCursorEventFactoryRuntime) == 0x34, "WxSetCursorEventFactoryRuntime size must be 0x34");

  class WxWindowCreateEventFactoryRuntime final : public wxCommandEventRuntime
  {
  public:
    WxWindowCreateEventFactoryRuntime()
      : wxCommandEventRuntime(EnsureWxEvtWindowCreateRuntimeType(), 0)
    {
      mEventObject = nullptr;
    }

    WxWindowCreateEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxWindowCreateEventFactoryRuntime(*this);
    }
  };
  static_assert(sizeof(WxWindowCreateEventFactoryRuntime) == 0x34, "WxWindowCreateEventFactoryRuntime size must be 0x34");

  class WxWindowDestroyEventFactoryRuntime final : public wxCommandEventRuntime
  {
  public:
    WxWindowDestroyEventFactoryRuntime()
      : wxCommandEventRuntime(EnsureWxEvtWindowDestroyRuntimeType(), 0)
    {
      mEventObject = nullptr;
    }

    WxWindowDestroyEventFactoryRuntime* Clone() const override
    {
      return new (std::nothrow) WxWindowDestroyEventFactoryRuntime(*this);
    }
  };
  static_assert(sizeof(WxWindowDestroyEventFactoryRuntime) == 0x34, "WxWindowDestroyEventFactoryRuntime size must be 0x34");

  /**
   * Address: 0x00979FB0 (FUN_00979FB0, wxConstructorForwxEvtHandler)
   *
   * What it does:
   * Allocates one wx event-handler runtime payload and seeds its core handler
   * chain/enable lanes with an empty lock pointer.
   */
  [[maybe_unused]] [[nodiscard]] void* wxConstructorForwxEvtHandler()
  {
    auto* const handler = new (std::nothrow) WxEvtHandlerFactoryRuntime();
    if (handler == nullptr) {
      return nullptr;
    }

    handler->mEventsLocker = ::operator new(0x18u, std::nothrow);
    return handler;
  }

  /**
   * Address: 0x0097A1C0 (FUN_0097A1C0, wxConstructorForwxScrollWinEvent)
   *
   * What it does:
   * Allocates one scroll-window event payload with null type and zeroed
   * command/extra lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxScrollWinEvent()
  {
    return new (std::nothrow) WxScrollWinEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A1F0 (FUN_0097A1F0, wxConstructorForwxMouseEvent)
   *
   * What it does:
   * Allocates one mouse-event payload with zeroed modifier/button/wheel lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxMouseEvent()
  {
    return new (std::nothrow) WxMouseEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A210 (FUN_0097A210, wxConstructorForwxKeyEvent)
   *
   * What it does:
   * Allocates one key-event payload with zeroed modifier/keycode/scancode
   * lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxKeyEvent()
  {
    return new (std::nothrow) WxKeyEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A390 (FUN_0097A390, wxConstructorForwxChildFocusEvent)
   *
   * What it does:
   * Allocates one child-focus command event payload and clears its event-object lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxChildFocusEvent()
  {
    return new (std::nothrow) WxChildFocusEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A630 (FUN_0097A630, wxConstructorForwxSetCursorEvent)
   *
   * What it does:
   * Allocates one set-cursor event payload with zeroed coordinates and cursor storage.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxSetCursorEvent()
  {
    return new (std::nothrow) WxSetCursorEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A860 (FUN_0097A860, wxConstructorForwxWindowCreateEvent)
   *
   * What it does:
   * Allocates one window-create command event payload and clears its source object.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxWindowCreateEvent()
  {
    return new (std::nothrow) WxWindowCreateEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A8D0 (FUN_0097A8D0, wxConstructorForwxWindowDestroyEvent)
   *
   * What it does:
   * Allocates one window-destroy command event payload and clears its source object.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxWindowDestroyEvent()
  {
    return new (std::nothrow) WxWindowDestroyEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A020 (FUN_0097A020, wxConstructorForwxIdleEvent)
   *
   * What it does:
   * Allocates one idle-event payload and initializes the request-more lane to
   * false.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxIdleEvent()
  {
    return new (std::nothrow) WxIdleEventRuntime();
  }

  /**
   * Address: 0x0097A060 (FUN_0097A060, wxConstructorForwxCommandEvent)
   *
   * What it does:
   * Allocates one command-event payload with default null type/id lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxCommandEvent()
  {
    return new (std::nothrow) wxCommandEventRuntime(0, 0);
  }

  /**
   * Address: 0x0097A140 (FUN_0097A140, wxConstructorForwxScrollEvent)
   *
   * What it does:
   * Allocates one scroll-event payload using command-event base initialization
   * and zeroed scroll lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxScrollEvent()
  {
    return new (std::nothrow) WxScrollEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A230 (FUN_0097A230, wxConstructorForwxSizeEvent)
   *
   * What it does:
   * Allocates one size-event payload and clears the width/height lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxSizeEvent()
  {
    return new (std::nothrow) WxSizeEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A270 (FUN_0097A270, wxConstructorForwxPaintEvent)
   *
   * What it does:
   * Allocates one paint-event payload with base wx event runtime lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxPaintEvent()
  {
    return new (std::nothrow) WxPaintEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A2A0 (FUN_0097A2A0, wxConstructorForwxNcPaintEvent)
   *
   * What it does:
   * Allocates one non-client paint-event payload with base wx event lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxNcPaintEvent()
  {
    return new (std::nothrow) WxNcPaintEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A2D0 (FUN_0097A2D0, wxConstructorForwxEraseEvent)
   *
   * What it does:
   * Allocates one erase-background event payload and clears the device-context
   * lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxEraseEvent()
  {
    return new (std::nothrow) WxEraseEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A310 (FUN_0097A310, wxConstructorForwxMoveEvent)
   *
   * What it does:
   * Allocates one move-event payload and clears cached move-position lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxMoveEvent()
  {
    return new (std::nothrow) WxMoveEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A350 (FUN_0097A350, wxConstructorForwxFocusEvent)
   *
   * What it does:
   * Allocates one focus-event payload and clears the focused-window lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxFocusEvent()
  {
    return new (std::nothrow) WxFocusEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A400 (FUN_0097A400, wxConstructorForwxCloseEvent)
   *
   * What it does:
   * Allocates one close-event payload and seeds veto/logging flags to
   * `(canVeto=true, veto=false, loggingOff=true)`.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxCloseEvent()
  {
    return new (std::nothrow) WxCloseEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A440 (FUN_0097A440, wxConstructorForwxShowEvent)
   *
   * What it does:
   * Allocates one show-event payload and seeds the shown-state lane to false.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxShowEvent()
  {
    return new (std::nothrow) WxShowEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A480 (FUN_0097A480, wxConstructorForwxMaximizeEvent)
   *
   * What it does:
   * Allocates one maximize-event payload with base wx event lanes only.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxMaximizeEvent()
  {
    return new (std::nothrow) WxMaximizeEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A4B0 (FUN_0097A4B0, wxConstructorForwxIconizeEvent)
   *
   * What it does:
   * Allocates one iconize-event payload and seeds the iconized-state lane to
   * true.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxIconizeEvent()
  {
    return new (std::nothrow) WxIconizeEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A4F0 (FUN_0097A4F0, wxConstructorForwxMenuEvent)
   *
   * What it does:
   * Allocates one menu-event payload and clears the selected menu-id lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxMenuEvent()
  {
    return new (std::nothrow) WxMenuEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A530 (FUN_0097A530, wxConstructorForwxJoystickEvent)
   *
   * What it does:
   * Allocates one joystick-event payload and clears all position/button
   * lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxJoystickEvent()
  {
    return new (std::nothrow) WxJoystickEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A580 (FUN_0097A580, wxConstructorForwxDropFilesEvent)
   *
   * What it does:
   * Allocates one drop-files event payload and clears file-count, drop-point,
   * and file-array lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxDropFilesEvent()
  {
    auto* const dropFilesEvent = new (std::nothrow) WxDropFilesEventRuntime();
    if (dropFilesEvent == nullptr) {
      return nullptr;
    }

    dropFilesEvent->mEventType = 0;
    dropFilesEvent->mFileCount = 0;
    dropFilesEvent->mDropPointX = 0;
    dropFilesEvent->mDropPointY = 0;
    dropFilesEvent->mFiles = nullptr;
    return dropFilesEvent;
  }

  /**
   * Address: 0x0097A5C0 (FUN_0097A5C0, wxConstructorForwxActivateEvent)
   *
   * What it does:
   * Allocates one activate-event payload and marks it active by default.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxActivateEvent()
  {
    return new (std::nothrow) WxActivateEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A600 (FUN_0097A600, wxConstructorForwxInitDialogEvent)
   *
   * What it does:
   * Allocates one init-dialog event payload with base wx-event lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxInitDialogEvent()
  {
    return new (std::nothrow) WxInitDialogEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A6A0 (FUN_0097A6A0, wxConstructorForwxSysColourChangedEvent)
   *
   * What it does:
   * Allocates one system-colour-changed event payload with base wx-event
   * lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxSysColourChangedEvent()
  {
    return new (std::nothrow) WxSysColourChangedEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A6D0 (FUN_0097A6D0, wxConstructorForwxDisplayChangedEvent)
   *
   * What it does:
   * Allocates one display-changed event payload with base wx-event lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxDisplayChangedEvent()
  {
    return new (std::nothrow) WxDisplayChangedEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A700 (FUN_0097A700, wxConstructorForwxUpdateUIEvent)
   *
   * What it does:
   * Allocates one update-UI command event payload and clears update lanes
   * (`checked/enabled/shown/text`) plus its text-label pointer lane.
   */
  [[nodiscard]] wxEventRuntime* wxConstructorForwxUpdateUIEvent()
  {
    return new (std::nothrow) WxUpdateUIEventRuntime();
  }

  /**
   * Address: 0x0097A7A0 (FUN_0097A7A0, wxConstructorForwxNavigationKeyEvent)
   *
   * What it does:
   * Allocates one navigation-key event payload and seeds default
   * `navigation-flags/current-focus` lanes.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxNavigationKeyEvent()
  {
    return new (std::nothrow) WxNavigationKeyEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A7E0 (FUN_0097A7E0, wxConstructorForwxPaletteChangedEvent)
   *
   * What it does:
   * Allocates one palette-changed event payload and clears changed-window
   * ownership lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxPaletteChangedEvent()
  {
    return new (std::nothrow) WxPaletteChangedEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A820 (FUN_0097A820, wxConstructorForwxQueryNewPaletteEvent)
   *
   * What it does:
   * Allocates one query-new-palette event payload and clears realized-state
   * lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxQueryNewPaletteEvent()
  {
    return new (std::nothrow) WxQueryNewPaletteEventFactoryRuntime();
  }

  /**
   * Address: 0x0097A9F0 (FUN_0097A9F0, wxConstructorForwxContextMenuEvent)
   *
   * What it does:
   * Allocates one context-menu event object, runs the command-event base
   * initialization lane, and seeds the event position with wx default
   * coordinates `(-1, -1)`.
   */
  [[nodiscard]] wxEventRuntime* wxConstructorForwxContextMenuEvent()
  {
    return new (std::nothrow) WxContextMenuEventRuntime();
  }

  /**
   * Address: 0x0097AA70 (FUN_0097AA70, wxConstructorForwxMouseCaptureChangedEvent)
   *
   * What it does:
   * Allocates one mouse-capture-changed event payload and clears the previous
   * capture window lane.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxMouseCaptureChangedEvent()
  {
    return new (std::nothrow)
      WxMouseCaptureChangedEventRuntime(0, EnsureWxEvtMouseCaptureChangedRuntimeType(), nullptr);
  }

  /**
   * Address: 0x0097A0D0 (FUN_0097A0D0, wxConstructorForwxNotifyEvent)
   *
   * What it does:
   * Allocates one notify-event payload lane, runs command-event base
   * initialization, and marks the event as allowed by default.
   */
  [[maybe_unused]] [[nodiscard]] wxEventRuntime* wxConstructorForwxNotifyEvent()
  {
    return new (std::nothrow) WxNotifyEventRuntime();
  }

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

  [[nodiscard]] WxLogFrameRuntimeState& EnsureWxLogFrameRuntimeState(
    const wxLogFrameRuntime* const frame
  )
  {
    return gWxLogFrameRuntimeStateByFrame[frame];
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
 * Address: 0x009674D0 (FUN_009674D0, wxIsShiftDown)
 *
 * What it does:
 * Returns whether the Win32 Shift key is currently pressed.
 */
bool wxIsShiftDown()
{
  return ::GetKeyState(VK_SHIFT) < 0;
}

/**
 * Address: 0x009674F0 (FUN_009674F0, wxIsCtrlDown)
 *
 * What it does:
 * Returns whether the Win32 Control key is currently pressed.
 */
bool wxIsCtrlDown()
{
  return ::GetKeyState(VK_CONTROL) < 0;
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

namespace
{
  struct ProcessWindowEnumContext
  {
    HWND matchedWindow = nullptr; // +0x00
    DWORD targetProcessId = 0;    // +0x04
  };
  static_assert(sizeof(ProcessWindowEnumContext) == 0x8, "ProcessWindowEnumContext size must be 0x8");

  /**
   * Address: 0x009C72B0 (FUN_009C72B0, EnumFunc)
   *
   * What it does:
   * EnumWindows callback that stores the first window owned by
   * `targetProcessId`, then stops enumeration.
   */
  BOOL CALLBACK EnumWindowForProcessId(const HWND window, const LPARAM contextParam)
  {
    auto* const context = reinterpret_cast<ProcessWindowEnumContext*>(contextParam);
    if (context == nullptr) {
      return TRUE;
    }

    DWORD ownerProcessId = 0;
    (void)::GetWindowThreadProcessId(window, &ownerProcessId);
    if (ownerProcessId != context->targetProcessId) {
      return TRUE;
    }

    context->matchedWindow = window;
    return FALSE;
  }
} // namespace

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
 * Address: 0x00962910 (FUN_00962910, wxLogTrace)
 *
 * What it does:
 * Preserves wx trace-log callsites as a no-op lane.
 */
void wxLogTrace(
  ...
)
{}

/**
 * Address: 0x00966E60 (FUN_00966E60, nullsub_3482)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackH()
{}

/**
 * Address: 0x00966E70 (FUN_00966E70, nullsub_3483)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackI()
{}

/**
 * Address: 0x00967010 (FUN_00967010, nullsub_3484)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1G(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00983420 (FUN_00983420, nullsub_3491)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1H(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00978200 (FUN_00978200, nullsub_3488)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackA()
{}

/**
 * Address: 0x00999B70 (FUN_00999B70, nullsub_3495)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x009A8EE0 (FUN_009A8EE0, nullsub_3496)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackB()
{}

/**
 * Address: 0x009AD4F0 (FUN_009AD4F0, nullsub_3501)
 *
 * What it does:
 * Preserves one `wxThread` vtable virtual lane as an intentional no-op.
 */
void wxThreadNoOpVirtualSlot()
{}

/**
 * Address: 0x009C5EE0 (FUN_009C5EE0, nullsub_3505)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2A(
  const std::int32_t reservedArg0,
  const std::int32_t reservedArg1
)
{
  static_cast<void>(reservedArg0);
  static_cast<void>(reservedArg1);
}

/**
 * Address: 0x009C5EF0 (FUN_009C5EF0, nullsub_3506)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2B(
  const std::int32_t reservedArg0,
  const std::int32_t reservedArg1
)
{
  static_cast<void>(reservedArg0);
  static_cast<void>(reservedArg1);
}

/**
 * Address: 0x009C5F00 (FUN_009C5F00, nullsub_3507)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1B(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x009C88E0 (FUN_009C88E0, nullsub_3509)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackC()
{}

/**
 * Address: 0x009C88F0 (FUN_009C88F0, nullsub_3510)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackD()
{}

/**
 * Address: 0x009C8900 (FUN_009C8900, nullsub_3511)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackE()
{}

/**
 * Address: 0x009C9DE0 (FUN_009C9DE0, nullsub_3512)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackJ()
{}

/**
 * Address: 0x009C9DF0 (FUN_009C9DF0, nullsub_3513)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackK()
{}

/**
 * Address: 0x009C9E00 (FUN_009C9E00, nullsub_3514)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackL()
{}

/**
 * Address: 0x009D2F00 (FUN_009D2F00, nullsub_3515)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackM()
{}

/**
 * Address: 0x00A06BF0 (FUN_00A06BF0, nullsub_3517)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1C(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00A07DD0 (FUN_00A07DD0, nullsub_3518)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with two stack arguments as
 * an intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall2C(
  const std::int32_t reservedArg0,
  const std::int32_t reservedArg1
)
{
  static_cast<void>(reservedArg0);
  static_cast<void>(reservedArg1);
}

/**
 * Address: 0x00A0B3F0 (FUN_00A0B3F0, nullsub_3519)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1D(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00A0DC40 (FUN_00A0DC40, nullsub_3520)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackF()
{}

/**
 * Address: 0x00A0E400 (FUN_00A0E400, nullsub_3521)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1I(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00A0E410 (FUN_00A0E410, nullsub_3522)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1J(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00A18DB0 (FUN_00A18DB0, nullsub_3523)
 *
 * What it does:
 * Preserves one wx runtime callback lane as an intentional no-op.
 */
void wxNoOpRuntimeCallbackG()
{}

/**
 * Address: 0x00A20780 (FUN_00A20780, nullsub_8)
 *
 * What it does:
 * Preserves one runtime function-pointer dispatch lane as an intentional
 * no-op.
 */
void wxNoOpRuntimeDispatchSlot()
{}

/**
 * Address: 0x00A27140 (FUN_00A27140, nullsub_3525)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1F(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x00A37F30 (FUN_00A37F30, nullsub_3526)
 *
 * What it does:
 * Preserves one stdcall wx runtime callback lane with one stack argument as an
 * intentional no-op.
 */
void __stdcall wxNoOpRuntimeStdCall1E(const std::int32_t reservedArg0)
{
  static_cast<void>(reservedArg0);
}

/**
 * Address: 0x009DD360 (FUN_009DD360, nullsub_3486)
 *
 * What it does:
 * No-op hook lane used by wx file-buffer flush helpers before commit/fflush
 * dispatch.
 */
void wxNoOpFileFlushHook()
{}

/**
 * Address: 0x009BCDD0 (FUN_009BCDD0, wxDeleteStockLists)
 *
 * What it does:
 * Releases each global wx stock-list singleton (brush, pen, font, bitmap)
 * and clears the stored singleton pointer lanes.
 */
void wxDeleteStockLists()
{
  DeleteStockList(wxTheBrushList);
  DeleteStockList(wxThePenList);
  DeleteStockList(wxTheFontList);
  DeleteStockList(wxTheBitmapList);
}

/**
 * Address: 0x009C4840 (FUN_009C4840)
 *
 * What it does:
 * Displays one fatal-message modal box (`MB_ICONHAND`) by dereferencing
 * pointer-stable wx string text/caption lanes supplied by caller-owned
 * `wxString` storage.
 */
int wxShowFatalMessageBoxFromStringStorage(
  const wchar_t* const* const titleText,
  const wchar_t* const* const messageText
)
{
  return ::MessageBoxW(nullptr, *messageText, *titleText, MB_ICONHAND);
}

/**
 * Address: 0x009C4860 (FUN_009C4860, wxSafeShowMessage)
 *
 * What it does:
 * Formats one fatal-log message into a fixed stack buffer, wraps both title
 * and message in temporary wx string storage, then shows the message box via
 * the pointer-based helper lane.
 */
int wxSafeShowMessage(
  const wchar_t* const formatText,
  va_list argList
)
{
  constexpr std::size_t kMessageBufferCount = 2048u;
  wchar_t messageBuffer[kMessageBufferCount]{};

  (void)std::vswprintf(messageBuffer, kMessageBufferCount, formatText, argList);
  messageBuffer[kMessageBufferCount - 1] = L'\0';

  wxStringRuntime message = AllocateOwnedWxString(messageBuffer);
  wxStringRuntime title = AllocateOwnedWxString(L"Fatal Error");

  const int result = wxShowFatalMessageBoxFromStringStorage(&title.m_pchData, &message.m_pchData);

  ReleaseOwnedWxString(title);
  ReleaseOwnedWxString(message);
  return result;
}

/**
 * Address: 0x009C4940 (FUN_009C4940, wxVLogFatalError)
 *
 * What it does:
 * Initializes one variadic argument lane, forwards the fatal message through
 * `wxSafeShowMessage`, and terminates the process with `abort()`.
 */
[[noreturn]] void wxVLogFatalError(
  wchar_t* const formatText,
  ...
)
{
  va_list argList;
  va_start(argList, formatText);
  (void)wxSafeShowMessage(formatText, argList);
  va_end(argList);
  std::abort();
}

/**
 * Address: 0x009C7D70 (FUN_009C7D70, wxColourDisplay)
 *
 * What it does:
 * Caches one display color-capability lane using `GetDeviceCaps(BITSPIXEL)`
 * and returns true when the current desktop device reports color output.
 */
BOOL wxColourDisplay()
{
  if (gWxColourDisplayCache == -1) {
    HDC const deviceContext = ::GetDC(nullptr);
    const int colorBits = ::GetDeviceCaps(deviceContext, BITSPIXEL);
    gWxColourDisplayCache = 0;
    if (colorBits == -1 || colorBits > 2) {
      gWxColourDisplayCache = 1;
    }
    (void)::ReleaseDC(nullptr, deviceContext);
  }

  return gWxColourDisplayCache != 0 ? TRUE : FALSE;
}

class wxListBaseRuntime
{
public:
  explicit wxListBaseRuntime(const std::int32_t) noexcept {}

  virtual ~wxListBaseRuntime() = default;
};

class wxBitmapListRuntime : public wxListBaseRuntime
{
public:
  wxBitmapListRuntime() noexcept
    : wxListBaseRuntime(0)
  {
  }
};

/**
 * Address: 0x009BCE40 (FUN_009BCE40, wxBitmapListInit)
 *
 * What it does:
 * Runs the stock wx bitmap-list constructor lane used by the global list
 * initializers.
 */
[[nodiscard]] wxBitmapListRuntime* wxBitmapListInit(wxBitmapListRuntime* const object) noexcept
{
  return new (object) wxBitmapListRuntime();
}

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
 * Address: 0x009F34B0 (FUN_009F34B0, wxSizer::DoSetClientObject)
 *
 * What it does:
 * Deletes the previous client-object payload (when present), then stores one
 * new client-object lane and marks payload type as object-backed.
 */
void wxSizerClientDataRuntime::DoSetClientObject(
  void* const clientObject
)
{
  if (mClientPayload != nullptr) {
    delete static_cast<wxClientDataRuntime*>(mClientPayload);
  }

  mClientPayload = clientObject;
  mClientPayloadType = kClientPayloadObject;
}

/**
 * Address: 0x009F34F0 (FUN_009F34F0, wxSizer::DoGetClientObject)
 *
 * What it does:
 * Returns the stored client payload pointer lane.
 */
void* wxSizerClientDataRuntime::DoGetClientObject() const
{
  return mClientPayload;
}

/**
 * Address: 0x009F3500 (FUN_009F3500, wxSizer::DoSetClientData)
 *
 * What it does:
 * Stores one raw client-data payload pointer and marks payload type as raw
 * client-data.
 */
void wxSizerClientDataRuntime::DoSetClientData(
  void* const clientData
)
{
  mClientPayload = clientData;
  mClientPayloadType = kClientPayloadData;
}

/**
 * Address: 0x009F3520 (FUN_009F3520, wxSizer::DoGetClientData)
 *
 * What it does:
 * Returns the stored client payload pointer lane.
 */
void* wxSizerClientDataRuntime::DoGetClientData() const
{
  return mClientPayload;
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
 * Address: 0x00A0AB50 (FUN_00A0AB50, wxLogFrame::wxLogFrame)
 * Mangled: ??0wxLogFrame@@QAE@PAVwxFrame@@PAVwxLogWindow@@PBD@Z
 *
 * What it does:
 * Builds one log-output frame lane, creates the embedded multiline text
 * control, and seeds log menu/status metadata.
 */
wxLogFrameRuntime::wxLogFrameRuntime(
  wxTopLevelWindowRuntime* const parentFrame,
  wxLogWindowRuntime* const ownerLogWindow,
  const wchar_t* const titleText
)
  : wxTopLevelWindowRuntime()
{
  constexpr long kWxLogFrameStyle = 0x20400E40;
  constexpr long kWxLogTextCtrlStyle = 0x40000030;
  constexpr wchar_t kFrameWindowName[] = L"frame";
  constexpr wchar_t kTextCtrlWindowName[] = L"text";

  mOwnerLogWindow = ownerLogWindow;
  mTextControl = new (std::nothrow) wxTextCtrlRuntime();

  WxWindowBaseRuntimeState& frameState = EnsureWxWindowBaseRuntimeState(this);
  frameState.parentWindow = static_cast<wxWindowBase*>(parentFrame);
  frameState.windowId = -1;
  frameState.windowStyle = kWxLogFrameStyle;
  frameState.windowName.assign(kFrameWindowName);

  if (mTextControl != nullptr) {
    WxWindowBaseRuntimeState& textState = EnsureWxWindowBaseRuntimeState(mTextControl);
    textState.parentWindow = this;
    textState.windowId = -1;
    textState.windowStyle = kWxLogTextCtrlStyle;
    textState.windowName.assign(kTextCtrlWindowName);
    EnsureWxTextCtrlRuntimeState(mTextControl).richEditMajorVersion = 0;
  }

  WxLogFrameRuntimeState& logFrameState = EnsureWxLogFrameRuntimeState(this);
  logFrameState.title.assign(titleText != nullptr ? titleText : L"");
  logFrameState.windowName.assign(kFrameWindowName);
  logFrameState.statusText.assign(L"Ready");
  logFrameState.textControl = mTextControl;
  logFrameState.ownerLogWindow = ownerLogWindow;
  logFrameState.menuReady = true;
}

wxTextCtrlRuntime* wxLogFrameRuntime::TextCtrl() const noexcept
{
  return mTextControl;
}

/**
 * Address: 0x00A0BC80 (FUN_00A0BC80, wxLogWindow::wxLogWindow)
 * Mangled: ??0wxLogWindow@@QAE@PAVwxFrame@@PBD_N2@Z
 *
 * What it does:
 * Initializes one log-window owner lane, allocates the backing log frame, and
 * shows that frame when requested by constructor arguments.
 */
wxLogWindowRuntime::wxLogWindowRuntime(
  wxTopLevelWindowRuntime* const parentFrame,
  const wchar_t* const titleText,
  const bool showAtStartup,
  const bool passToOldLog
)
{
  std::memset(mUnknown04To0F, 0, sizeof(mUnknown04To0F));
  mPassToOldLog = passToOldLog ? 1u : 0u;
  mFrame = new (std::nothrow) wxLogFrameRuntime(parentFrame, this, titleText);
  if (showAtStartup && mFrame != nullptr) {
    (void)mFrame->Show(true);
  }
}

wxLogFrameRuntime* wxLogWindowRuntime::GetFrame() const noexcept
{
  return mFrame;
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
 * Address: 0x009C7EF0 (FUN_009C7EF0, wxGetWindowId)
 *
 * What it does:
 * Returns one Win32 window-id lane (`GWL_ID`) from the provided native HWND.
 */
long wxGetWindowId(void* const nativeWindow) noexcept
{
  return ::GetWindowLongW(static_cast<HWND>(nativeWindow), GWL_ID);
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
  gWxLogFrameRuntimeStateByFrame.erase(reinterpret_cast<const wxLogFrameRuntime*>(frame));
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

/**
 * Address: 0x00992B90 (FUN_00992B90, wxEntryStart)
 *
 * IDA signature:
 * BOOL sub_992B90();
 *
 * What it does:
 * Runs wx startup initialization and returns the success flag as `bool`.
 */
bool wxEntryStart()
{
  return wxApp::Initialize();
}

/**
 * Address: 0x00992020 (FUN_00992020, wxEntryInitGui)
 *
 * What it does:
 * Invokes `wxTheApp->OnInitGui()` and returns the virtual-call success lane.
 */
bool wxEntryInitGui()
{
  return wxTheApp->OnInitGui();
}

/**
 * Address: 0x00992FE0 (FUN_00992FE0, wxEntryCleanup)
 *
 * IDA signature:
 * void __cdecl wxEntryCleanup();
 *
 * What it does:
 * Runs wx shutdown cleanup used by the `wxEntry` exit path.
 */
void wxEntryCleanup()
{
  wxApp::CleanUp();
}

/**
 * Address: 0x00968990 (FUN_00968990, wxYieldForCommandsOnly)
 *
 * What it does:
 * Pumps only `WM_COMMAND` messages from the current thread queue and routes
 * each through `wxApp::ProcessMessage`; reposts quit state when `WM_QUIT` is
 * observed.
 */
void wxYieldForCommandsOnly()
{
  MSG commandMessage{};
  const UINT commandMessageId = WM_COMMAND;

  while (::PeekMessageW(&commandMessage, nullptr, commandMessageId, commandMessageId, PM_REMOVE) != FALSE) {
    if (commandMessage.message == WM_QUIT) {
      break;
    }

    if (wxTheApp != nullptr) {
      (void)wxTheApp->ProcessMessage(reinterpret_cast<void**>(&commandMessage));
    }
  }

  if (commandMessage.message == WM_QUIT) {
    ::PostQuitMessage(0);
  }
}

msvc8::vector<moho::ManagedWindowSlot> moho::managedWindows{};
msvc8::vector<moho::ManagedWindowSlot> moho::managedFrames{};
wxWindowBase* moho::sMainWindow = nullptr;
moho::WRenViewport* moho::ren_Viewport = nullptr;
void* moho::WBitmapPanel::sm_eventTable[1] = {nullptr};
void* moho::WBitmapCheckBox::sm_eventTable[1] = {nullptr};
void* moho::WRenViewport::sm_eventTable[1] = {nullptr};

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
moho::CD3DPrimBatcher* moho::WD3DViewport::GetPrimBatcher() const
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
 * Address: 0x00A312A0 (FUN_00A312A0, sub_A312A0)
 *
 * What it does:
 * Formats one DDE error-code lane into a human-readable wx string payload.
 */
wxStringRuntime* wxFormatDdeErrorString(
  wxStringRuntime* const outText,
  const unsigned int ddeErrorCode
)
{
  if (outText == nullptr) {
    return nullptr;
  }

  ReleaseOwnedWxString(*outText);

  const auto assignLiteral = [outText](const wchar_t* const text) -> wxStringRuntime* {
    AssignOwnedWxString(outText, text != nullptr ? std::wstring(text) : std::wstring());
    return outText;
  };

  switch (ddeErrorCode) {
  case 0x0000u:
    return assignLiteral(L"no DDE error.");
  case 0x4000u:
    return assignLiteral(L"a request for a synchronous advise transaction has timed out.");
  case 0x4001u:
    return assignLiteral(L"the response to the transaction caused the DDE_FBUSY bit to be set.");
  case 0x4002u:
    return assignLiteral(L"a request for a synchronous data transaction has timed out.");
  case 0x4003u:
    return assignLiteral(
      L"a DDEML function was called without first calling the DdeInitialize function,\n"
      L"or an invalid instance identifier\n"
      L"was passed to a DDEML function."
    );
  case 0x4004u:
    return assignLiteral(
      L"an application initialized as APPCLASS_MONITOR has\n"
      L"attempted to perform a DDE transaction,\n"
      L"or an application initialized as APPCMD_CLIENTONLY has \n"
      L"attempted to perform server transactions."
    );
  case 0x4005u:
    return assignLiteral(L"a request for a synchronous execute transaction has timed out.");
  case 0x4006u:
    return assignLiteral(L"a parameter failed to be validated by the DDEML.");
  case 0x4007u:
    return assignLiteral(L"a DDEML application has created a prolonged race condition.");
  case 0x4008u:
    return assignLiteral(L"a memory allocation failed.");
  case 0x4009u:
    return assignLiteral(L"a transaction failed.");
  case 0x400Au:
    return assignLiteral(L"a client's attempt to establish a conversation has failed.");
  case 0x400Bu:
    return assignLiteral(L"a request for a synchronous poke transaction has timed out.");
  case 0x400Cu:
    return assignLiteral(L"an internal call to the PostMessage function has failed. ");
  case 0x400Du:
    return assignLiteral(L"reentrancy problem.");
  case 0x400Eu:
    return assignLiteral(
      L"a server-side transaction was attempted on a conversation\n"
      L"that was terminated by the client, or the server\n"
      L"terminated before completing a transaction."
    );
  case 0x400Fu:
    return assignLiteral(L"an internal error has occurred in the DDEML.");
  case 0x4010u:
    return assignLiteral(L"a request to end an advise transaction has timed out.");
  case 0x4011u:
    return assignLiteral(
      L"an invalid transaction identifier was passed to a DDEML function.\n"
      L"Once the application has returned from an XTYP_XACT_COMPLETE callback,\n"
      L"the transaction identifier for that callback is no longer valid."
    );
  default:
    break;
  }

  std::array<wchar_t, 64> unknownMessage{};
  std::swprintf(unknownMessage.data(), unknownMessage.size(), L"Unknown DDE error %08x", ddeErrorCode);
  AssignOwnedWxString(outText, std::wstring(unknownMessage.data()));
  return outText;
}

namespace
{
  struct ChildProcessMonitorThreadContext
  {
    HWND notificationWindow = nullptr;           // +0x00
    HANDLE childProcessHandle = nullptr;         // +0x04
    DWORD childProcessId = 0;                    // +0x08
    void* ownerContext = nullptr;                // +0x0C
    DWORD childProcessExitCode = 0;              // +0x10
    std::uint8_t completionPending = 0;          // +0x14
    std::uint8_t reserved15_17[3] = {0, 0, 0};  // +0x15
  };

  static_assert(
    offsetof(ChildProcessMonitorThreadContext, notificationWindow) == 0x00,
    "ChildProcessMonitorThreadContext::notificationWindow offset must be 0x00"
  );
  static_assert(
    offsetof(ChildProcessMonitorThreadContext, childProcessHandle) == 0x04,
    "ChildProcessMonitorThreadContext::childProcessHandle offset must be 0x04"
  );
  static_assert(
    offsetof(ChildProcessMonitorThreadContext, childProcessId) == 0x08,
    "ChildProcessMonitorThreadContext::childProcessId offset must be 0x08"
  );
  static_assert(
    offsetof(ChildProcessMonitorThreadContext, ownerContext) == 0x0C,
    "ChildProcessMonitorThreadContext::ownerContext offset must be 0x0C"
  );
  static_assert(
    offsetof(ChildProcessMonitorThreadContext, childProcessExitCode) == 0x10,
    "ChildProcessMonitorThreadContext::childProcessExitCode offset must be 0x10"
  );
  static_assert(
    offsetof(ChildProcessMonitorThreadContext, completionPending) == 0x14,
    "ChildProcessMonitorThreadContext::completionPending offset must be 0x14"
  );
  static_assert(
    sizeof(ChildProcessMonitorThreadContext) == 0x18,
    "ChildProcessMonitorThreadContext size must be 0x18"
  );

  constexpr UINT kChildProcessCompletedMessage = WM_PALETTEISCHANGING | 0x2800u;
} // namespace

/**
 * Address: 0x00A133F0 (FUN_00A133F0, StartAddress)
 *
 * What it does:
 * Waits for a launched child process, records its exit code in the shared
 * monitor context, and notifies the hidden window that completion arrived.
 */
DWORD WINAPI StartAddress(
  LPVOID const lpThreadParameter
)
{
  auto* const threadContext = static_cast<ChildProcessMonitorThreadContext*>(lpThreadParameter);
  ::WaitForSingleObject(threadContext->childProcessHandle, INFINITE);
  ::GetExitCodeProcess(threadContext->childProcessHandle, &threadContext->childProcessExitCode);
  ::SendMessageW(
    threadContext->notificationWindow,
    kChildProcessCompletedMessage,
    0,
    reinterpret_cast<LPARAM>(threadContext)
  );
  return 0;
}

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

/**
 * Address: 0x00A94D8C (FUN_00A94D8C, wxOpen)
 *
 * What it does:
 * Opens one wide filesystem path with `_SH_DENYNO` sharing via CRT secure
 * open dispatch and returns either the file descriptor or `-1`.
 */
int wxOpen(
  const wchar_t* const fileName,
  const int openFlags,
  const int permissions
)
{
  int fileDescriptor = -1;
  if (_wsopen_s(&fileDescriptor, fileName, openFlags, _SH_DENYNO, permissions) != 0) {
    return -1;
  }
  return fileDescriptor;
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

  const int openFlags = _O_BINARY | _O_RDONLY;
  m_fd = wxOpen(fileName, openFlags, permissions);
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
 * Address: 0x0096E1D0 (FUN_0096E1D0, wxNativeFontInfo::wxNativeFontInfo)
 * Mangled: ??0wxNativeFontInfo@@QAE@@Z
 *
 * What it does:
 * Constructs one native-font descriptor and seeds default runtime lanes.
 */
wxNativeFontInfoRuntime::wxNativeFontInfoRuntime()
{
  Init();
}

/**
 * Address: 0x0097EEF0 (FUN_0097EEF0, wxNativeFontInfo::FromString)
 * Mangled: ?FromString@wxNativeFontInfo@@QAE_NABVwxString@@@Z
 *
 * What it does:
 * Resets this descriptor, tokenizes one textual font descriptor, and applies
 * style/weight/underline/point-size/charset/facename lanes.
 */
bool wxNativeFontInfoRuntime::FromString(
  const wxStringRuntime& description
)
{
  Init();

  std::wstring pendingFaceName{};
  const std::vector<std::wstring> tokens = SplitNativeFontDescriptionTokens(description.c_str());

  auto flushPendingFaceName = [&]() {
    if (pendingFaceName.empty()) {
      return;
    }

    SetFaceName(wxStringRuntime::Borrow(pendingFaceName.c_str()));
    pendingFaceName.clear();
  };

  for (const std::wstring& token : tokens) {
    const std::wstring lowered = ToLowerWide(token);
    bool recognized = false;

    if (lowered == L"underlined") {
      SetUnderlined(true);
      recognized = true;
    } else if (lowered == L"light") {
      SetWeight(91);
      recognized = true;
    } else if (lowered == L"bold" || ContainsNoCase(lowered, L"bold")) {
      SetWeight(92);
      recognized = true;
    } else if (lowered == L"italic" || ContainsNoCase(lowered, L"italic")) {
      SetStyle(93);
      recognized = true;
    } else {
      std::int32_t pointSize = 0;
      if (TryParseIntToken(lowered, &pointSize)) {
        SetPointSize(pointSize);
        recognized = true;
      } else {
        std::int32_t charset = 0;
        if (TryMapEncodingToCharset(lowered, &charset)) {
          SetEncoding(charset);
          recognized = true;
        }
      }
    }

    if (recognized) {
      flushPendingFaceName();
      continue;
    }

    if (!pendingFaceName.empty()) {
      pendingFaceName.push_back(L' ');
    }
    pendingFaceName += token;
  }

  flushPendingFaceName();
  return true;
}

/**
 * Address: 0x0097F440 (FUN_0097F440, wxFontBase::SetNativeFontInfo)
 * Mangled: ?SetNativeFontInfo@wxFontBase@@QAEXABVwxString@@@Z
 *
 * What it does:
 * Parses one textual native-font descriptor and forwards the parsed
 * descriptor into virtual slot `+0x68` on the font object.
 */
void WX_FontBaseSetNativeFontInfoFromString(
  void* const fontObject,
  const wxStringRuntime& description
)
{
  if (fontObject == nullptr) {
    return;
  }

  const wchar_t* const text = description.c_str();
  if (text == nullptr || *text == L'\0') {
    return;
  }

  wxNativeFontInfoRuntime nativeFontInfo{};
  if (!nativeFontInfo.FromString(description)) {
    return;
  }

  void** const vtable = *reinterpret_cast<void***>(fontObject);
  if (vtable == nullptr) {
    return;
  }

  using SetNativeInfoFn = std::int32_t(__thiscall*)(void*, const wxNativeFontInfoRuntime&);
  auto const setNativeInfo = reinterpret_cast<SetNativeInfoFn>(vtable[0x68 / sizeof(void*)]);
  (void)setNativeInfo(fontObject, nativeFontInfo);
}

void wxNativeFontInfoRuntime::Init() noexcept
{
  mHeight = 0;
  mWidth = 0;
  mEscapement = 0;
  mOrientation = 0;
  mWeight = 400;
  mItalic = 0;
  mUnderline = 0;
  mStrikeOut = 0;
  mCharSet = 1;
  mOutPrecision = 0;
  mClipPrecision = 0;
  mQuality = 0;
  mPitchAndFamily = 0;
  std::wmemset(mFaceName, 0, std::size(mFaceName));
}

void wxNativeFontInfoRuntime::SetPointSize(
  const std::int32_t pointSize
) noexcept
{
  mHeight = pointSize > 0 ? pointSize : 0;
}

void wxNativeFontInfoRuntime::SetWeight(
  const std::int32_t weight
) noexcept
{
  if (weight == 91) {
    mWeight = 300;
    return;
  }

  if (weight == 92) {
    mWeight = 700;
    return;
  }

  mWeight = weight;
}

void wxNativeFontInfoRuntime::SetStyle(
  const std::int32_t style
) noexcept
{
  mItalic = style == 93 ? 1u : 0u;
}

void wxNativeFontInfoRuntime::SetUnderlined(
  const bool underlined
) noexcept
{
  mUnderline = underlined ? 1u : 0u;
}

void wxNativeFontInfoRuntime::SetFaceName(
  const wxStringRuntime& faceName
) noexcept
{
  std::wmemset(mFaceName, 0, std::size(mFaceName));

  const wchar_t* const text = faceName.c_str();
  if (text == nullptr || *text == L'\0') {
    return;
  }

  const std::size_t len = std::wcslen(text);
  const std::size_t copyLen = (std::min)(len, std::size(mFaceName) - 1u);
  if (copyLen > 0u) {
    std::wmemcpy(mFaceName, text, copyLen);
    mFaceName[copyLen] = L'\0';
  }
}

void wxNativeFontInfoRuntime::SetEncoding(
  const std::int32_t encoding
) noexcept
{
  mCharSet = static_cast<std::uint8_t>(encoding & 0xFF);
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

/**
 * Address: 0x00976400 (FUN_00976400, wxCreateDIB)
 *
 * What it does:
 * Allocates one palette-backed DIB header block, seeds its metadata, and
 * converts the palette entries into bitmap color-table order for the caller.
 */
bool wxCreateDIB(
  const std::int32_t xSize,
  const std::int32_t ySize,
  const std::int32_t bitsPerPixel,
  HPALETTE hpal,
  LPBITMAPINFO* const lpDIBHeader
)
{
  auto* const dibHeader = static_cast<LPBITMAPINFO>(std::malloc(0x428u));
  ::GetPaletteEntries(hpal, 0, 0x100u, reinterpret_cast<LPPALETTEENTRY>(dibHeader->bmiColors));

  dibHeader->bmiHeader.biPlanes = 0;
  dibHeader->bmiHeader.biXPelsPerMeter = 0;
  dibHeader->bmiHeader.biYPelsPerMeter = 0;
  dibHeader->bmiHeader.biClrImportant = 0;
  dibHeader->bmiHeader.biHeight = ySize;
  dibHeader->bmiHeader.biWidth = xSize;
  dibHeader->bmiHeader.biSizeImage = (bitsPerPixel * xSize * std::abs(ySize)) >> 3;
  dibHeader->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
  dibHeader->bmiHeader.biPlanes = 1;
  dibHeader->bmiHeader.biBitCount = static_cast<WORD>(bitsPerPixel);
  dibHeader->bmiHeader.biCompression = BI_RGB;
  dibHeader->bmiHeader.biClrUsed = 0x100;

  auto* const paletteEntries = reinterpret_cast<const PALETTEENTRY*>(dibHeader->bmiColors);
  auto* const rgbQuads = dibHeader->bmiColors;
  for (std::int32_t index = 0; index < 0x100; ++index) {
    const PALETTEENTRY paletteEntry = paletteEntries[index];
    rgbQuads[index].rgbBlue = paletteEntry.peBlue;
    rgbQuads[index].rgbGreen = paletteEntry.peGreen;
    rgbQuads[index].rgbRed = paletteEntry.peRed;
    rgbQuads[index].rgbReserved = paletteEntry.peFlags;
  }

  *lpDIBHeader = dibHeader;
  return true;
}

/**
 * Address: 0x009764C0 (FUN_009764C0, wxFreeDIB)
 *
 * What it does:
 * Releases one DIB header block previously allocated by `wxCreateDIB()`.
 */
void wxFreeDIB(void* const ptr)
{
  _free_crt(ptr);
}

/**
 * Address: 0x009C6900 (FUN_009C6900, wxRGBToColour)
 *
 * What it does:
 * Initializes one `wxColourRuntime` from packed `0x00BBGGRR` RGB bytes and
 * returns the output pointer.
 */
wxColourRuntime* wxRGBToColour(wxColourRuntime* const outColour, const std::uint32_t packedRgb)
{
  if (outColour == nullptr) {
    return nullptr;
  }

  const std::uint8_t red = static_cast<std::uint8_t>(packedRgb & 0xFFu);
  const std::uint8_t green = static_cast<std::uint8_t>((packedRgb >> 8u) & 0xFFu);
  const std::uint8_t blue = static_cast<std::uint8_t>((packedRgb >> 16u) & 0xFFu);
  *outColour = wxColourRuntime::FromRgb(red, green, blue);
  return outColour;
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

wxCommandEventRuntime* wxCommandEventRuntime::Clone() const
{
  auto* const clone = new (std::nothrow) wxCommandEventRuntime();
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
  AssignOwnedWxString(&clone->mCommandString, std::wstring(mCommandString.c_str()));
  clone->mCommandInt = mCommandInt;
  clone->mExtraLong = mExtraLong;
  clone->mClientData = mClientData;
  clone->mClientObject = mClientObject;
  return clone;
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

namespace
{
  struct wxListItemInternalDataRuntime
  {
    wxListItemAttrRuntime* attr = nullptr; // +0x00
    LPARAM lParam = 0;                     // +0x04
  };

  static_assert(
    offsetof(wxListItemInternalDataRuntime, attr) == 0x0,
    "wxListItemInternalDataRuntime::attr offset must be 0x0"
  );
  static_assert(
    offsetof(wxListItemInternalDataRuntime, lParam) == 0x4,
    "wxListItemInternalDataRuntime::lParam offset must be 0x4"
  );
  static_assert(sizeof(wxListItemInternalDataRuntime) == 0x8, "wxListItemInternalDataRuntime size must be 0x8");

  /**
   * Address: 0x0099BC70 (FUN_0099BC70, wxGetInternalData)
   *
   * What it does:
   * Requests one list-view row and returns the internal lParam payload when
   * the native `LVM_GETITEMW` query succeeds.
   */
  [[nodiscard]] wxListItemInternalDataRuntime* wxGetInternalData(
    const LPARAM itemId,
    const HWND listHandle
  )
  {
    LVITEMW item{};
    item.mask = LVIF_PARAM;
    item.iItem = static_cast<int>(itemId);

    const LRESULT queryResult = ::SendMessageW(listHandle, LVM_GETITEMW, 0, reinterpret_cast<LPARAM>(&item));
    return queryResult != 0 ? reinterpret_cast<wxListItemInternalDataRuntime*>(item.lParam) : nullptr;
  }

  /**
   * Address: 0x0099BCA0 (FUN_0099BCA0, wxGetInternalData_0)
   *
   * What it does:
   * Resolves the list-view HWND for one control instance and forwards to
   * `wxGetInternalData`.
   */
  [[nodiscard]] wxListItemInternalDataRuntime* wxGetInternalData_0(
    wxListCtrlRuntime* const listControl,
    const LPARAM itemId
  )
  {
    const HWND listHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(listControl->GetHandle()));
    return wxGetInternalData(itemId, listHandle);
  }

  /**
   * Address: 0x0099BCD0 (FUN_0099BCD0, wxConvertFromMSWListItem)
   *
   * What it does:
   * Converts one native `LVITEMW` payload into runtime `wxListItem` lanes,
   * including state-bit translation and optional text retrieval.
   */
  void wxConvertFromMSWListItem(
    LVITEMW* const mswItem,
    wxListItemRuntime* const item,
    const HWND listHandle
  )
  {
    if (const auto* const internalData = reinterpret_cast<wxListItemInternalDataRuntime*>(mswItem->lParam);
      internalData != nullptr) {
      item->mData = internalData->lParam;
    }

    item->mMask = 0;
    item->mState = 0;
    item->mStateMask = 0;
    item->mItemId = mswItem->iItem;

    const UINT originalMask = mswItem->mask;
    UINT restoredMask = mswItem->mask;
    bool allocatedTextBuffer = false;

    if (listHandle != nullptr) {
      if ((originalMask & LVIF_TEXT) == 0u) {
        allocatedTextBuffer = true;
        mswItem->pszText = static_cast<LPWSTR>(::operator new(0x402u));
        mswItem->cchTextMax = 512;
      }

      mswItem->mask |= (LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM);
      (void)::SendMessageW(listHandle, LVM_GETITEMW, 0, reinterpret_cast<LPARAM>(mswItem));
      restoredMask = originalMask;
    }

    if ((mswItem->mask & LVIF_STATE) != 0u) {
      item->mMask |= 0x1;

      if ((mswItem->stateMask & 0x4u) != 0u) {
        item->mStateMask |= 0x8;
        if ((mswItem->state & 0x4u) != 0u) {
          item->mState |= 0x8;
        }
      }

      if ((mswItem->stateMask & 0x8u) != 0u) {
        item->mStateMask |= 0x1;
        if ((mswItem->state & 0x8u) != 0u) {
          item->mState |= 0x1;
        }
      }

      if ((mswItem->stateMask & 0x1u) != 0u) {
        item->mStateMask |= 0x2;
        if ((mswItem->state & 0x1u) != 0u) {
          item->mState |= 0x2;
        }
      }

      if ((mswItem->stateMask & 0x2u) != 0u) {
        item->mStateMask |= 0x4;
        if ((mswItem->state & 0x2u) != 0u) {
          item->mState |= 0x4;
        }
      }
    }

    if ((mswItem->mask & LVIF_TEXT) != 0u) {
      item->mMask |= 0x2;
      AssignOwnedWxString(&item->mText, mswItem->pszText != nullptr ? std::wstring(mswItem->pszText) : std::wstring{});
      restoredMask = originalMask;
    }

    if ((mswItem->mask & LVIF_IMAGE) != 0u) {
      item->mMask |= 0x4;
      item->mImage = mswItem->iImage;
    }

    if ((mswItem->mask & LVIF_PARAM) != 0u) {
      item->mMask |= 0x8;
    }

    if ((mswItem->mask & LVIF_INDENT) != 0u) {
      item->mMask |= 0x10;
    }

    item->mColumn = mswItem->iSubItem;

    if (allocatedTextBuffer && mswItem->pszText != nullptr) {
      ::operator delete(mswItem->pszText);
      mswItem->mask = originalMask;
    } else {
      mswItem->mask = restoredMask;
    }
  }
} // namespace

/**
 * Address: 0x0099BCB0 (FUN_0099BCB0, wxGetInternalDataAttr)
 *
 * What it does:
 * Returns the optional per-row list-item attribute payload lane for one
 * list-control row id.
 */
wxListItemAttrRuntime* wxGetInternalDataAttr(
  const LPARAM itemId,
  wxListCtrlRuntime* const listControl
)
{
  wxListItemInternalDataRuntime* const internalData = wxGetInternalData_0(listControl, itemId);
  return internalData != nullptr ? internalData->attr : nullptr;
}

/**
 * Address: 0x0099D910 (FUN_0099D910, wxDeleteInternalData)
 *
 * What it does:
 * Clears one row's native list-view lParam lane, then destroys retained
 * wx-list-item internal attribute/data payload storage.
 */
void wxDeleteInternalData(
  const LPARAM itemId,
  wxListCtrlRuntime* const listControl
)
{
  wxListItemInternalDataRuntime* const internalData = wxGetInternalData_0(listControl, itemId);
  if (internalData == nullptr) {
    return;
  }

  LVITEMW item{};
  item.mask = LVIF_PARAM;
  item.iItem = static_cast<int>(itemId);

  const HWND listHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(listControl->GetHandle()));
  (void)::SendMessageW(listHandle, LVM_SETITEMW, 0, reinterpret_cast<LPARAM>(&item));

  if (internalData->attr != nullptr) {
    DestroyWxListItemAttrRuntime(internalData->attr);
    ::operator delete(internalData->attr);
  }

  ::operator delete(internalData);
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
  constexpr unsigned int kSupComFrameSysCommandSize = SC_SIZE;
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
 * Address: 0x008CE060 (FUN_008CE060, WSupComFrame::dtr)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for SupCom frame runtime lanes.
 */
WSupComFrame* WSupComFrame::DeleteWithFlag(
  WSupComFrame* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  gSupComFrameStateByFrame.erase(object);
  WX_FrameDestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }

  return object;
}

/**
 * Address: 0x008CDAA0 (FUN_008CDAA0, WSupComFrame::OnCloseWindow)
 *
 * What it does:
 * Exits the wx main loop when the frame is iconized; otherwise requests the
 * Moho escape dialog.
 */
void WSupComFrame::OnCloseWindow(
  wxCloseEventRuntime& event
)
{
  (void)event;

  if (IsIconized()) {
    wxTheApp->ExitMainLoop();
    return;
  }

  (void)moho::ShowEscapeDialog(true);
}

/**
 * Address: 0x008CDCD0 (FUN_008CDCD0, WSupComFrame::MSWDefWindowProc)
 *
 * What it does:
 * Handles SupCom system-command defaults, including pending-maximize sync
 * priming and Alt-menu suppression, then forwards remaining lanes through
 * base wx default-window-proc dispatch.
 */
long WSupComFrame::MSWDefWindowProc(
  const unsigned int message,
  const unsigned int wParam,
  const long lParam
)
{
  auto dispatchBase = [this, message, wParam, lParam]() -> long {
    return wxTopLevelWindowRuntime::MSWDefWindowProc(message, wParam, lParam);
  };

  if (message != kSupComFrameMessageSysCommand) {
    return dispatchBase();
  }

  if ((wParam & 0xFFF0u) == kSupComFrameSysCommandSize) {
    mPendingMaximizeSync = 1;
    if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
      (void)device->Clear2(true);
    }
  }

  if (wParam == kSupComFrameSysCommandKeyMenu && lParam == 0) {
    return 0;
  }

  return dispatchBase();
}

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
  /**
   * Address: 0x007FB730 (FUN_007FB730, boost::shared_ptr_CD3DPrimBatcher::operator=)
   *
   * What it does:
   * Rebinds one `shared_ptr<CD3DPrimBatcher>` from a raw pointer and releases
   * prior ownership.
   */
  boost::shared_ptr<moho::CD3DPrimBatcher>* AssignSharedPrimBatcherFromRaw(
    boost::shared_ptr<moho::CD3DPrimBatcher>* const outPrimBatcher,
    moho::CD3DPrimBatcher* const primBatcher
  )
  {
    outPrimBatcher->reset(primBatcher);
    return outPrimBatcher;
  }

  /**
   * Address: 0x007FB7C0 (FUN_007FB7C0, boost::shared_ptr_IRenTerrain::operator=)
   *
   * What it does:
   * Rebinds one `shared_ptr<TerrainCommon>` from a raw pointer and releases
   * prior ownership.
   */
  boost::shared_ptr<moho::TerrainCommon>* AssignSharedTerrainFromRaw(
    boost::shared_ptr<moho::TerrainCommon>* const outTerrain,
    moho::TerrainCommon* const terrain
  )
  {
    outTerrain->reset(terrain);
    return outTerrain;
  }

  struct WRenViewportWorldViewParamRuntime final
  {
    moho::IRenderWorldView* view;           // +0x00
    std::int32_t head;                      // +0x04
    std::int32_t depth;                     // +0x08
    boost::shared_ptr<moho::TerrainCommon> terrain; // +0x0C
  };
  static_assert(offsetof(WRenViewportWorldViewParamRuntime, depth) == 0x08);
  static_assert(offsetof(WRenViewportWorldViewParamRuntime, terrain) == 0x0C);
  static_assert(sizeof(WRenViewportWorldViewParamRuntime) == 0x14);

  struct WRenViewportWorldViewVectorRuntime final
  {
    WRenViewportWorldViewParamRuntime* mFirst; // +0x00
    WRenViewportWorldViewParamRuntime* mLast;  // +0x04
    WRenViewportWorldViewParamRuntime* mEnd;   // +0x08
  };
  static_assert(sizeof(WRenViewportWorldViewVectorRuntime) == 0x0C);

  struct WRenViewportRenderView final
  {
    struct DebugCanvasRuntimeView final
    {
      moho::CD3DPrimBatcher* mPrimBatcher = nullptr; // +0x00
      std::uint8_t mUnknown04To3F[0x3C]{};
    };

    static_assert(sizeof(DebugCanvasRuntimeView) == 0x40, "WRenViewportRenderView::DebugCanvasRuntimeView size must be 0x40");

    std::uint8_t mUnknown0000_2147[0x2148];
    WRenViewportWorldViewVectorRuntime mWorldViews; // +0x2148
    std::uint8_t mUnknown2154_215B[0x08];
    DebugCanvasRuntimeView mDebugCanvas;
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
    Wm3::Vector2i mFullScreen; // +0x318
    std::int32_t mHead; // +0x320
    std::uint8_t mUnknown324_4EF[0x1CC];
    struct ShadowView final
    {
      std::uint8_t mUnknown00_07[0x08];
      std::int32_t shadow_Fidelity; // +0x08
    };
    ShadowView mShadowRenderer; // +0x4F0
  };

  struct WRenViewportPreviewImageView final
  {
    std::uint8_t mUnknown0000_2193[0x2194];
    moho::WPreviewImageRuntime mPreviewImage; // +0x2194
  };

  struct WRenViewportReflectionPassView final
  {
    struct ReflectionRenderTargetSlot final
    {
      moho::ID3DRenderTarget* mRenderTarget; // +0x00
      void* mWriterLock;                      // +0x04
    };

    struct ReflectionDepthStencilSlot final
    {
      moho::ID3DDepthStencil* mDepthStencil; // +0x00
      void* mWriterLock;                      // +0x04
    };

    ReflectionRenderTargetSlot mRenderTargetSlots[2]; // +0x00
    ReflectionDepthStencilSlot mDepthStencilSlots[2]; // +0x10
  };

  static_assert(sizeof(WRenViewportReflectionPassView::ReflectionRenderTargetSlot) == 0x08);
  static_assert(sizeof(WRenViewportReflectionPassView::ReflectionDepthStencilSlot) == 0x08);
  static_assert(sizeof(WRenViewportReflectionPassView) == 0x20);

  static_assert(
    offsetof(WRenViewportRenderView, mDebugCanvas) == 0x215C,
    "WRenViewportRenderView::mDebugCanvas offset must be 0x215C"
  );
  static_assert(
    offsetof(WRenViewportRenderView, mWorldViews) == 0x2148,
    "WRenViewportRenderView::mWorldViews offset must be 0x2148"
  );
  static_assert(
    offsetof(WRenViewportRenderView, mCam) == 0x219C, "WRenViewportRenderView::mCam offset must be 0x219C"
  );
  static_assert(
    offsetof(WRenViewportPreviewImageView, mPreviewImage) == 0x2194,
    "WRenViewportPreviewImageView::mPreviewImage offset must be 0x2194"
  );
#if defined(MOHO_ABI_MSVC8_COMPAT)
  static_assert(
    offsetof(WRenViewportRenderView, mFullScreen) == 0x318,
    "WRenViewportRenderView::mFullScreen offset must be 0x318"
  );
#endif
  [[nodiscard]] WRenViewportRenderView* AsRenderView(moho::WRenViewport* const viewport) noexcept
  {
    return reinterpret_cast<WRenViewportRenderView*>(viewport);
  }

  [[nodiscard]] WRenViewportReflectionPassView* AsReflectionPassView(WRenViewportRenderView* const runtime) noexcept
  {
    auto* const bytes = reinterpret_cast<std::uint8_t*>(runtime);
    return reinterpret_cast<WRenViewportReflectionPassView*>(bytes + 0x2174);
  }

  [[nodiscard]] msvc8::vector<WRenViewportWorldViewParamRuntime>* AsWorldViewVector(
    WRenViewportRenderView* const runtime
  ) noexcept
  {
    auto* const bytes = reinterpret_cast<std::uint8_t*>(runtime);
    return reinterpret_cast<msvc8::vector<WRenViewportWorldViewParamRuntime>*>(bytes + 0x2144);
  }

} // namespace

namespace moho
{
  extern bool ren_Fx;
  extern bool ren_ShowSkeletons;
  extern bool ren_Water;
  extern bool ren_Reflection;
} // namespace moho

/**
 * Address: 0x004F1E50 (FUN_004F1E50, Moho::MohoApp::OnInit)
 * Mangled: ?OnInit@MohoApp@Moho@@UAE_NXZ
 *
 * What it does:
 * Returns startup success for the app bootstrap lane.
 */
bool moho::MohoApp::OnInit()
{
  return true;
}

/**
 * Address: 0x004F1E80 (FUN_004F1E80, Moho::MohoApp::ExitMainLoop)
 * Mangled: ?ExitMainLoop@MohoApp@Moho@@UAEXXZ
 *
 * What it does:
 * Clears the loop-keepalive flag so wx main-loop pumping exits.
 */
void moho::MohoApp::ExitMainLoop()
{
  m_keepGoing = 0;
}

/**
 * Address: 0x007F6530 (FUN_007F6530, Moho::REN_ShowSkeletons)
 *
 * What it does:
 * Toggles skeleton-debug rendering and mirrors that bool into the active
 * sim-driver sync option lane when a driver instance exists.
 */
void moho::REN_ShowSkeletons()
{
  const bool showSkeletons = !moho::ren_ShowSkeletons;
  moho::ren_ShowSkeletons = showSkeletons;

  if (ISTIDriver* const simDriver = moho::SIM_GetActiveDriver(); simDriver != nullptr) {
    simDriver->SetSyncFilterOptionFlag(showSkeletons);
  }
}

/**
 * Address: 0x007FA170 (FUN_007FA170, ?REN_GetTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
 *
 * What it does:
 * Returns the active world-map terrain resource when one is available.
 */
moho::IWldTerrainRes* moho::REN_GetTerrainRes()
{
  moho::CWldSession* const session = moho::WLD_GetActiveSession();
  if (session == nullptr || session->mWldMap == nullptr) {
    return nullptr;
  }

  return session->mWldMap->mTerrainRes;
}

/**
 * Address: 0x004FBCB0 (FUN_004FBCB0, ?GetEventTable@WBitmapPanel@Moho@@MBEPBUwxEventTable@@XZ)
 * Mangled: ?GetEventTable@WBitmapPanel@Moho@@MBEPBUwxEventTable@@XZ
 *
 * What it does:
 * Returns the static event-table lane for this bitmap-panel runtime type.
 */
const void* moho::WBitmapPanel::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x004FBE20 (FUN_004FBE20, ?GetEventTable@WBitmapCheckBox@Moho@@MBEPBUwxEventTable@@XZ)
 * Mangled: ?GetEventTable@WBitmapCheckBox@Moho@@MBEPBUwxEventTable@@XZ
 *
 * What it does:
 * Returns the static event-table lane for this bitmap-check-box runtime type.
 */
const void* moho::WBitmapCheckBox::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x007F65D0 (FUN_007F65D0, ?GetPreviewImage@WRenViewport@Moho@@UAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
 *
 * What it does:
 * Returns one retained preview-image shared-pointer lane from viewport
 * runtime storage.
 */
moho::WPreviewImageRuntime moho::WRenViewport::GetPreviewImage() const
{
  const auto* const runtime = reinterpret_cast<const WRenViewportPreviewImageView*>(this);
  WPreviewImageRuntime previewImage = runtime->mPreviewImage;
  if (previewImage.lane1 != nullptr) {
    auto* const refCount = reinterpret_cast<volatile long*>(reinterpret_cast<std::uint8_t*>(previewImage.lane1) + 0x04u);
    (void)InterlockedIncrement(refCount);
  }
  return previewImage;
}

/**
 * Address: 0x007F6690 (FUN_007F6690, ?GetEventTable@WRenViewport@Moho@@MBEPBUwxEventTable@@XZ)
 * Mangled: ?GetEventTable@WRenViewport@Moho@@MBEPBUwxEventTable@@XZ
 *
 * What it does:
 * Returns the static event-table lane for this viewport runtime type.
 */
const void* moho::WRenViewport::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x007F6600 (FUN_007F6600, ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ)
 * Mangled: ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ
 *
 * What it does:
 * Returns the viewport debug-canvas primary batcher lane.
 */
moho::CD3DPrimBatcher* moho::WRenViewport::GetPrimBatcher() const
{
  const WRenViewportRenderView* const runtime = AsRenderView(const_cast<WRenViewport*>(this));
  return runtime->mDebugCanvas.mPrimBatcher;
}

/**
 * Address: 0x007F6610 (FUN_007F6610, ?OnMouseEnter@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z)
 *
 * What it does:
 * Focuses the primary GAL head window when the mouse enters the render
 * viewport and device runtime is ready.
 */
void moho::WRenViewport::OnMouseEnter(wxMouseEventRuntime& mouseEvent)
{
  (void)mouseEvent;

  if (!gpg::gal::Device::IsReady()) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  if (device == nullptr) {
    return;
  }

  gpg::gal::DeviceContext* const context = device->GetDeviceContext();
  if (context == nullptr || context->GetHeadCount() <= 0) {
    return;
  }

  const gpg::gal::Head& head = context->GetHead(0);
  if (head.mWindow != nullptr) {
    (void)::SetFocus(reinterpret_cast<HWND>(head.mWindow));
  }
}

void moho::WRenViewport::ResetRenderState0C() noexcept
{
  mRenderState0C = -1;
}

/**
 * Address: 0x007F9E60 (FUN_007F9E60, ?AddWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@HH@Z)
 *
 * What it does:
 * Inserts one world-view lane sorted by depth and initializes one terrain
 * renderer lane for that world-view entry.
 *
 * Notes:
 * The binary uses global `ren_Viewport` as the active owner lane.
 */
void moho::WRenViewport::AddWorldView(
  IRenderWorldView* const worldView,
  const int head,
  const int depth
)
{
  WRenViewport* const viewport = moho::ren_Viewport;
  viewport->RemoveWorldView(worldView);

  WRenViewportRenderView* const runtime = AsRenderView(viewport);
  WRenViewportWorldViewParamRuntime* insertPos = runtime->mWorldViews.mFirst;
  for (WRenViewportWorldViewParamRuntime* it = runtime->mWorldViews.mLast; insertPos != it; ++insertPos) {
    if (depth < insertPos->depth) {
      break;
    }
  }

  WRenViewportWorldViewParamRuntime entry{};
  entry.view = worldView;
  entry.head = head;
  entry.depth = depth;
  (void)AssignSharedTerrainFromRaw(&entry.terrain, moho::IRenTerrain::Create());
  if (entry.terrain) {
    (void)entry.terrain->Create(reinterpret_cast<moho::TerrainWaterResourceView*>(moho::REN_GetTerrainRes()));
  }

  msvc8::vector<WRenViewportWorldViewParamRuntime>* const worldViews = AsWorldViewVector(runtime);
  std::size_t insertIndex = 0;
  if (runtime->mWorldViews.mFirst != nullptr && insertPos != nullptr) {
    insertIndex = static_cast<std::size_t>(insertPos - runtime->mWorldViews.mFirst);
  }

  worldViews->push_back(WRenViewportWorldViewParamRuntime{});
  WRenViewportWorldViewParamRuntime* const begin = worldViews->begin();
  WRenViewportWorldViewParamRuntime* dst = worldViews->end() - 1;
  WRenViewportWorldViewParamRuntime* const target = begin + insertIndex;
  while (dst != target) {
    *dst = std::move(*(dst - 1));
    --dst;
  }

  *dst = std::move(entry);
}

/**
 * Address: 0x007FA090 (FUN_007FA090, ?RemoveWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@@Z)
 *
 * What it does:
 * Removes the first matching world-view lane from the viewport world-view
 * vector at `+0x2148`.
 */
void moho::WRenViewport::RemoveWorldView(IRenderWorldView* const worldView)
{
  WRenViewportRenderView* const runtime = AsRenderView(this);
  msvc8::vector<WRenViewportWorldViewParamRuntime>* const worldViews = AsWorldViewVector(runtime);
  WRenViewportWorldViewParamRuntime* const first = runtime->mWorldViews.mFirst;
  WRenViewportWorldViewParamRuntime* const last = runtime->mWorldViews.mLast;
  if (first == nullptr || last == nullptr || first == last || worldViews == nullptr) {
    return;
  }

  for (WRenViewportWorldViewParamRuntime* it = first; it != last; ++it) {
    if (it->view != worldView) {
      continue;
    }

    worldViews->erase(it);
    return;
  }
}

/**
 * Address: 0x007F81C0 (FUN_007F81C0, ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the active viewport render target and viewport lanes, renders terrain
 * normal-composite data with optional shadow lane, then emits terrain skirt
 * geometry for the same frame.
 */
void moho::WRenViewport::RenderCompositeTerrain(TerrainCommon* const terrain)
{
  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(runtime->mHead, false, 0, 1.0f, 0);
  device->SetColorWriteState(true, false);
  SetViewportToLocalScreen();

  (void)terrain;
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
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, true);

  moho::Shadow* const shadowRenderer = runtime->mShadowRenderer.shadow_Fidelity != 0
    ? reinterpret_cast<moho::Shadow*>(&runtime->mShadowRenderer)
    : nullptr;

  moho::MeshRenderer* const instance = moho::MeshRenderer::GetInstance();
  if (moho::ren_ShowSkeletons) {
    instance->RenderSkeletons(
      reinterpret_cast<moho::CD3DPrimBatcher*>(runtime->mPrimBatcher.batcher),
      reinterpret_cast<moho::CDebugCanvas*>(&runtime->mDebugCanvas),
      *cam,
      true
    );
    return;
  }

  instance->Render(meshFlags, *cam, shadowRenderer, instance->meshes);
  (void)mirrored;
}

/**
 * Address: 0x007F8560 (FUN_007F8560, Moho::WRenViewport::RenderEffects)
 *
 * What it does:
 * Binds the viewport render target and viewport lanes for the active head,
 * configures color writes for FX, then renders world-particle effects.
 */
void moho::WRenViewport::RenderEffects(const bool renderWaterSurface)
{
  if (!moho::ren_Fx) {
    return;
  }

  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(runtime->mHead, false, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, false);

  (void)moho::sWorldParticles.RenderEffects(
    runtime->mCam,
    static_cast<char>(renderWaterSurface ? 1 : 0),
    0,
    moho::REN_GetGameTick(),
    moho::REN_GetSimDeltaSeconds()
  );
}

/**
 * Address: 0x007F86F0 (FUN_007F86F0, ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the active viewport head to the water render target, restores the
 * viewport rectangle, and forwards the current frame lanes to terrain water
 * rendering.
 */
void moho::WRenViewport::RenderWater(TerrainCommon* const terrain)
{
  if (!moho::ren_Water) {
    return;
  }

  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(runtime->mHead, false, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, true);

  (void)terrain;
}

/**
 * Address: 0x007F7DF0 (FUN_007F7DF0, ?RenderReflections@WRenViewport@Moho@@AAEXXZ)
 *
 * What it does:
 * Binds reflection render-target/depth lanes for the active head slot and,
 * when enabled, renders reflection meshes through `MeshRenderer`.
 */
void moho::WRenViewport::RenderReflections()
{
  if (!moho::ren_Water) {
    return;
  }

  WRenViewportRenderView* const runtime = AsRenderView(this);
  WRenViewportReflectionPassView* const reflectionView = AsReflectionPassView(runtime);
  moho::CD3DDevice* const colorDevice = moho::D3D_GetDevice();
  moho::CD3DDevice* const targetDevice = moho::D3D_GetDevice();
  const std::size_t reflectionIndex = static_cast<std::size_t>(runtime->mHead);
  targetDevice->SetRenderTarget1(
    reflectionView->mRenderTargetSlots[reflectionIndex].mRenderTarget,
    reflectionView->mDepthStencilSlots[reflectionIndex].mDepthStencil,
    true,
    0,
    1.0f,
    0
  );

  if (!moho::ren_Reflection) {
    return;
  }
  SetViewportToLocalScreen();
  colorDevice->SetColorWriteState(true, true);

  moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
  renderer->Render(2, *runtime->mCam, nullptr, renderer->meshes);
}

/**
 * Address: 0x007F7EA0 (FUN_007F7EA0, ?SetViewportToLocalScreen@WRenViewport@Moho@@AAEXXZ)
 *
 * What it does:
 * Applies this viewport's cached local-screen rectangle to the active D3D
 * device viewport state.
 */
void moho::WRenViewport::SetViewportToLocalScreen()
{
  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetViewport(&runtime->mScreenPos, &runtime->mScreenSize, 0.0f, 1.0f);
}

/**
 * Address: 0x007F87F0 (FUN_007F87F0, ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Refreshes full-head dimensions and local viewport lanes from the active
 * camera's viewport matrix row when a camera is present, else falls back to
 * the full-head rectangle.
 */
void moho::WRenViewport::UpdateRenderViewportCoordinates()
{
  WRenViewportRenderView* const runtime = AsRenderView(this);

  moho::CD3DDevice* const widthDevice = moho::D3D_GetDevice();
  const int headWidth = widthDevice->GetHeadWidth(static_cast<unsigned int>(runtime->mHead));
  moho::CD3DDevice* const heightDevice = moho::D3D_GetDevice();
  const int headHeight = heightDevice->GetHeadHeight(static_cast<unsigned int>(runtime->mHead));
  runtime->mFullScreen.x = headWidth;
  runtime->mFullScreen.y = headHeight;

  moho::GeomCamera3* const camera = runtime->mCam;
  if (camera != nullptr) {
    runtime->mScreenPos.x = static_cast<int>(camera->viewport.r[3].x);
    runtime->mScreenPos.y = static_cast<int>(camera->viewport.r[3].y);
    runtime->mScreenSize.x = static_cast<int>(camera->viewport.r[3].z);
    runtime->mScreenSize.y = static_cast<int>(camera->viewport.r[3].w);
    return;
  }

  runtime->mScreenSize.x = headWidth;
  runtime->mScreenSize.y = runtime->mFullScreen.y;
  runtime->mScreenPos.x = 0;
  runtime->mScreenPos.y = 0;
}

/**
 * Address: 0x007F8B70 (FUN_007F8B70, ?FogOff@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?FogOff@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Disables fog on the active GAL D3D9 device with default depth range
 * (`0.0f..1.0f`) and zero fog color lanes.
 */
void moho::WRenViewport::FogOff()
{
  gpg::gal::DeviceD3D9* const device = static_cast<gpg::gal::DeviceD3D9*>(gpg::gal::Device::GetInstance());
  device->SetFogState(false, nullptr, 0.0f, 1.0f, 0);
}

/**
 * Address: 0x007F7F10 (FUN_007F7F10, ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the viewport's terrain-normal render target and viewport lanes, then
 * dispatches terrain-normal rendering when terrain debug rendering is enabled.
 */
void moho::WRenViewport::RenderTerrainNormals(TerrainCommon* const terrain)
{
  if (terrain == nullptr) {
    return;
  }

  WRenViewportRenderView* const runtime = AsRenderView(this);
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  gpg::gal::DeviceD3D9* const d3dDevice = device->GetDeviceD3D9();
  if (d3dDevice != nullptr) {
    (void)d3dDevice->ClearTextures();
  }

  device->SetRenderTarget2(runtime->mHead, true, 0, 1.0f, 0);
  SetViewportToLocalScreen();
}
