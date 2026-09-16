#pragma once

#include <cstddef>
#include <cstdint>

/**
 * Runtime class-info placeholder used by recovered wx core/GDI lanes.
 */
struct wxClassInfoRuntime
{
  void* lane = nullptr;
};

static_assert(sizeof(wxClassInfoRuntime) == 0x4, "wxClassInfoRuntime size must be 0x4");

/**
 * Minimal recovered wxObject runtime base.
 */
class wxObjectRuntime
{
public:
  /**
   * Address: 0x0042AD90 (FUN_0042AD90)
   * Mangled: ??0wxObject@@QAE@@Z
   *
   * What it does:
   * Initializes base wx object lanes and clears ref-data ownership.
   */
  wxObjectRuntime();

  /**
   * Address: 0x0042ADA0 (FUN_0042ADA0)
   * Mangled: ??1wxObject@@QAE@XZ
   *
   * What it does:
   * Releases ref-data ownership through the shared unref lane.
   */
  virtual ~wxObjectRuntime();

protected:
  void ReleaseRefData() noexcept;

  void* mRefData = nullptr;
};

static_assert(sizeof(wxObjectRuntime) == 0x8, "wxObjectRuntime size must be 0x8");

/**
 * Minimal recovered wx GDI object runtime base.
 */
class wxGDIObjectRuntime : public wxObjectRuntime
{
public:
  /**
   * Address: 0x0042AE50 (FUN_0042AE50)
   * Mangled: ??0wxGDIObject@@QAE@@Z
   *
   * What it does:
   * Seeds the runtime-visible lane to false with empty ref-data ownership.
   */
  wxGDIObjectRuntime();

  /**
   * Address: 0x0042AE70 (FUN_0042AE70)
   * Mangled: ?RealizeResource@wxGDIObject@@UAE_NXZ
   *
   * What it does:
   * Default base implementation reports no realizable native resource.
   */
  [[nodiscard]] virtual bool RealizeResource();

  /**
   * Address: 0x0042AE80 (FUN_0042AE80)
   * Mangled: ?FreeResource@wxGDIObject@@UAE_NK@Z
   *
   * What it does:
   * Default base implementation reports no resource to free.
   */
  [[nodiscard]] virtual bool FreeResource(std::uintptr_t resourceHandle);

  /**
   * Address: 0x0042AE90 (FUN_0042AE90)
   * Mangled: ?IsFree@wxGDIObject@@UBE_NXZ
   *
   * What it does:
   * Base implementation reports this object as not free.
   */
  [[nodiscard]] virtual bool IsFree() const;

  /**
   * Address: 0x0042AEA0 (FUN_0042AEA0)
   * Mangled: ?GetResourceHandle@wxGDIObject@@UBEKXZ
   *
   * What it does:
   * Base implementation exposes no native resource handle.
   */
  [[nodiscard]] virtual std::uintptr_t GetResourceHandle() const;

  /**
   * Address: 0x0042AEB0 (FUN_0042AEB0)
   * Mangled: ?GetVisible@wxGDIObject@@QBE_NXZ
   *
   * What it does:
   * Returns the runtime visibility lane.
   */
  [[nodiscard]] virtual bool GetVisible() const;

  /**
   * Address: 0x0042AEC0 (FUN_0042AEC0)
   * Mangled: ?SetVisible@wxGDIObject@@QAEE_N@Z
   *
   * What it does:
   * Stores one runtime visibility value and returns it.
   */
  virtual bool SetVisible(bool visible);

  /**
   * Address: 0x0042AED0 (FUN_0042AED0)
   * Mangled: ?GetClassInfo@wxGDIObject@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns static class-info storage for wxGDIObject runtime checks.
   */
  [[nodiscard]] virtual const wxClassInfoRuntime* GetClassInfo() const;

protected:
  std::uint8_t mVisible = 0;
  std::uint8_t mPadding09[3]{};
};

static_assert(sizeof(wxGDIObjectRuntime) == 0xC, "wxGDIObjectRuntime size must be 0xC");

/**
 * Minimal recovered wxFontBase runtime lane.
 */
class wxFontBaseRuntime : public wxGDIObjectRuntime
{
public:
  /**
   * Address: 0x0042AF20 (FUN_0042AF20)
   * Mangled: ?SetNoAntiAliasing@wxFontBase@@UAEX_N@Z
   *
   * What it does:
   * Base implementation accepts but ignores anti-aliasing policy.
   */
  virtual void SetNoAntiAliasing(bool disabled);

  /**
   * Address: 0x0042AF30 (FUN_0042AF30)
   * Mangled: ?GetNoAntiAliasing@wxFontBase@@UBE_NXZ
   *
   * What it does:
   * Base implementation reports anti-aliasing enabled.
   */
  [[nodiscard]] virtual bool GetNoAntiAliasing() const;

  /**
   * Address: 0x0042AFE0 (FUN_0042AFE0)
   * Mangled: ??1wxFontBase@@UAE@XZ
   *
   * What it does:
   * Destroys wxFontBase through wxObject ref-data release semantics.
   */
  ~wxFontBaseRuntime() override;
};

/**
 * Minimal recovered wxFont runtime lane.
 */
class wxFontRuntimeObject : public wxFontBaseRuntime
{
public:
  /**
   * Address: 0x0042AF40 (FUN_0042AF40)
   * Mangled: ??0wxFont@@QAE@@Z
   *
   * What it does:
   * Initializes base lanes and performs font runtime init hook.
   */
  wxFontRuntimeObject();

  /**
   * Address: 0x0096E9F0 (FUN_0096E9F0)
   * Mangled: ??1wxFont@@QAE@@Z
   *
   * What it does:
   * Tears down wxFont runtime lanes and releases base wxObject ref-data state.
   */
  ~wxFontRuntimeObject() override;

  /**
   * Address: 0x0042AF90 (FUN_0042AF90)
   * Mangled: ?GetClassInfo@wxFont@@UBEPAVwxClassInfo@@XZ
   *
   * What it does:
   * Returns static class-info storage for wxFont runtime checks.
   */
  [[nodiscard]] const wxClassInfoRuntime* GetClassInfo() const override;

private:
  void Init() noexcept;
};

static_assert(sizeof(wxFontRuntimeObject) == 0xC, "wxFontRuntimeObject size must be 0xC");

/**
 * Minimal recovered wxColour runtime lane.
 *
 * `wxColour` derives from `wxObject` directly (not `wxGDIObject`) and never
 * shares ref-data between copies in this build: every constructor - default,
 * from-components, and copy - stores its own colour lanes by value and
 * leaves `mRefData` untouched at the base class's default-initialized
 * `nullptr`. That is why the copy constructor below delegates to
 * `wxObjectRuntime`'s default constructor instead of copying the source's
 * ref-data pointer: `wxColour::wxColour(const wxColour&)`
 * (0x0096FB10) does exactly that on the binary side (`this->m_refData = 0;`
 * ahead of the five field copies), and the destructor never needs to unref
 * anything beyond the always-null base lane.
 */
class wxColourRuntimeObject : public wxObjectRuntime
{
public:
  wxColourRuntimeObject() noexcept = default;

  // Not itself tied to one decompiled address - this is the ordinary
  // from-components constructor (real wx: `wxColour(r, g, b)`, `Set()`)
  // used here only to seed the stock black/white colour constants
  // `wxDCBase::wxDCBase` copy-constructs its text colours from.
  wxColourRuntimeObject(
    const std::uint8_t red,
    const std::uint8_t green,
    const std::uint8_t blue
  ) noexcept
    : mPixel((static_cast<std::uint32_t>(blue) << 16) | (static_cast<std::uint32_t>(green) << 8) | red)
    , mIsInit(true)
    , mRed(red)
    , mBlue(blue)
    , mGreen(green)
  {}

  /**
   * Address: 0x0096FB10 (FUN_0096FB10)
   * Mangled: ??0wxColour@@QAE@ABV0@@Z
   *
   * What it does:
   * Copies the packed pixel value and the four colour component lanes from
   * `other`; ref-data ownership is never shared, matching the binary.
   */
  wxColourRuntimeObject(const wxColourRuntimeObject& other) noexcept;

  [[nodiscard]] std::uint8_t Red() const noexcept { return mRed; }
  [[nodiscard]] std::uint8_t Green() const noexcept { return mGreen; }
  [[nodiscard]] std::uint8_t Blue() const noexcept { return mBlue; }
  [[nodiscard]] bool IsOk() const noexcept { return mIsInit != 0; }
  [[nodiscard]] std::uint32_t GetPixel() const noexcept { return mPixel; }

private:
  std::uint32_t mPixel = 0;  // +0x08, WXCOLORREF
  bool mIsInit = false;      // +0x0C
  std::uint8_t mRed = 0;     // +0x0D
  std::uint8_t mBlue = 0;    // +0x0E
  std::uint8_t mGreen = 0;   // +0x0F
};

static_assert(sizeof(wxColourRuntimeObject) == 0x10, "wxColourRuntimeObject size must be 0x10");

/**
 * `wxGDIImage` in this wx build (`wx/msw/gdiimage.h`) is a pure pass-through
 * base over `wxGDIObject` - it declares native-format conversion virtuals
 * but adds no data of its own, and its constructor
 * (0x004F17A0) does nothing but chain to `wxGDIObject::wxGDIObject` and
 * re-stamp its own vtable. Modelled as a thin alias rather than a
 * data-bearing layer for exactly that reason.
 */
class wxGDIImageRuntime : public wxGDIObjectRuntime
{
public:
  /**
   * Address: 0x004F17A0 (FUN_004F17A0)
   * Mangled: ??0wxGDIImage@@QAE@@Z
   *
   * What it does:
   * Chains to the `wxGDIObject` base state (ref-data cleared, not visible);
   * carries no lanes of its own.
   */
  wxGDIImageRuntime() noexcept;
};

/**
 * Minimal recovered wxBitmap runtime lane (the default/"null" state only -
 * this project never constructs a populated bitmap through this lane).
 */
class wxBitmapRuntimeObject : public wxGDIImageRuntime
{
public:
  /**
   * Address: 0x004F3310 (FUN_004F3310)
   * Mangled: ??0wxBitmap@@QAE@@Z
   *
   * What it does:
   * Builds an invalid ("null") bitmap: chains through the `wxGDIImage` /
   * `wxGDIObject` base state and stamps this class's own vtable. The
   * binary's third step (`call FUN_00975AF0`) targets a one-byte `retn` -
   * an empty compiler-emitted body with no observable effect - so it is not
   * reproduced here; see FUN_00975AF0's own progress note.
   */
  wxBitmapRuntimeObject() noexcept;
};

static_assert(sizeof(wxBitmapRuntimeObject) == 0xC, "wxBitmapRuntimeObject size must be 0xC");

// wx's shared pen/brush style enumeration (wxWindows-2.4.2 include/wx/defs.h:
// styles from 1456, joins from 1478, caps from 1482). The engine folds these
// straight into the instruction stream, so they are named here from the
// vendored header rather than inferred from the values: the join and cap runs
// are adjacent and trivially transposed.
inline constexpr std::int32_t kWxStyleSolid = 100;         // wxSOLID
inline constexpr std::int32_t kWxStyleDot = 101;           // wxDOT
inline constexpr std::int32_t kWxStyleLongDash = 102;      // wxLONG_DASH
inline constexpr std::int32_t kWxStyleShortDash = 103;     // wxSHORT_DASH
inline constexpr std::int32_t kWxStyleDotDash = 104;       // wxDOT_DASH
inline constexpr std::int32_t kWxStyleUserDash = 105;      // wxUSER_DASH
inline constexpr std::int32_t kWxStyleTransparent = 106;   // wxTRANSPARENT
inline constexpr std::int32_t kWxPenJoinRound = 122;       // wxJOIN_ROUND
inline constexpr std::int32_t kWxPenCapRound = 130;        // wxCAP_ROUND

// wxWindows-2.4.2 include/wx/defs.h:485 enumerates the OS families from
// `wxUNKNOWN_PLATFORM = 0`; `wxWIN32S` is the twentieth entry.
inline constexpr int kWxPlatformWin32s = 19;               // wxWIN32S

// Declared with its full address block in WxRuntimeTypes.h (0x009C7540); the
// GDI layer sits below that header and only needs the signature, so it is
// forward-declared rather than pulling the whole wx runtime header in here.
int wxGetOsVersion(int* majorVsn, int* minorVsn);


/**
 * Minimal recovered wxBrush ref-data lane: the shared, ref-counted payload
 * a `wxBrushRuntimeObject` points `mRefData` at once it owns a real brush.
 *
 * Offsets are read off the constructor at 0x009D2570, which writes every
 * one of them: `m_count`(ref count, from `wxObjectRefData`) at +0x04,
 * `m_style` at +0x08, an embedded `wxBitmap m_stipple` value at +0x0C, an
 * embedded `wxColour m_colour` value at +0x18, and `m_hBrush` at +0x28 -
 * `operator new(0x2Cu)` confirms the total size.
 */
class wxBrushRefDataRuntimeObject
{
public:
  /**
   * Address: 0x009D2570 (FUN_009D2570)
   * Mangled: ??0wxBrushRefData@@QAE@ABVwxColour@@H@Z
   *
   * What it does:
   * Seeds a one-owner ref count, stores the requested style and colour, and
   * leaves the stipple bitmap and native handle empty.
   */
  wxBrushRefDataRuntimeObject(
    const wxColourRuntimeObject& colour,
    const std::int32_t style
  ) noexcept;

  // `wxGDIRefData : wxObjectRefData` supplies this vtable slot; a plain
  // virtual destructor reproduces it without modelling the (empty) base
  // classes separately.
  virtual ~wxBrushRefDataRuntimeObject() = default;

  [[nodiscard]] std::int32_t Style() const noexcept { return mStyle; }
  [[nodiscard]] const wxColourRuntimeObject& Colour() const noexcept { return mColour; }

  // Matches `wxObject::Ref`/`wxEvent::UnRef`'s intrusive counting for this
  // payload: callers share a brush by bumping the count, and release it by
  // dropping the count and freeing once nothing references it any more.
  void AddRef() noexcept { ++mRefCount; }
  [[nodiscard]] bool ReleaseRef() noexcept { return --mRefCount == 0; }

private:
  std::int32_t mRefCount = 1;         // +0x04 (wxObjectRefData::m_count)
  std::int32_t mStyle = 0;            // +0x08
  wxBitmapRuntimeObject mStipple{};   // +0x0C
  wxColourRuntimeObject mColour{};    // +0x18
  void* mNativeBrushHandle = nullptr; // +0x28 (WXHBRUSH)
};

static_assert(sizeof(wxBrushRefDataRuntimeObject) == 0x2C, "wxBrushRefDataRuntimeObject size must be 0x2C");

/**
 * Minimal recovered wxBrush runtime lane.
 *
 * Every constructor stores its ref-data pointer through the shared
 * `wxObjectRuntime::mRefData` lane; this project never dereferences a
 * brush's ref-data as anything but an opaque shared payload (`SetBrush`
 * selects the *native* handle produced elsewhere, never this object), so
 * `wxBrushRefDataRuntimeObject` is allocated and owned but not otherwise
 * read back through this class.
 */
class wxBrushRuntimeObject : public wxGDIObjectRuntime
{
public:
  /**
   * Address: 0x009C8760 (FUN_009C8760)
   * Mangled: ??0wxBrush@@QAE@@Z
   *
   * What it does:
   * Default-constructs an empty ("null") brush: no ref-data, not visible.
   */
  wxBrushRuntimeObject() noexcept;

  /**
   * Address: 0x009D2860 (FUN_009D2860)
   * Mangled: ??0wxBrush@@QAE@ABV0@@Z
   *
   * What it does:
   * Shares the source brush's ref-data (`wxObject::Ref`): points at the same
   * payload and bumps its ref count, matching the binary's
   * `wxObject::Ref(this, a2)` tail call.
   */
  wxBrushRuntimeObject(const wxBrushRuntimeObject& other) noexcept;

  /**
   * Address: 0x009D2880 (FUN_009D2880)
   * Mangled: ??0wxBrush@@QAE@ABVwxColour@@H@Z
   *
   * What it does:
   * Allocates a fresh, single-owner `wxBrushRefData` for the given
   * colour/style pair, matching `operator new(0x2Cu)` plus the ref-data
   * constructor in the binary.
   */
  wxBrushRuntimeObject(const wxColourRuntimeObject& colour, std::int32_t style);

  /**
   * Address: 0x009D2910 (FUN_009D2910)
   * Mangled: ??1wxBrush@@QAE@XZ
   *
   * What it does:
   * Drops this instance's share of the ref-data (`wxEvent::UnRef`),
   * freeing the shared payload once nothing references it any more.
   */
  ~wxBrushRuntimeObject() override;

  // wxBrush::GetStyle() is already recovered as the generic
  // wxGetNestedRuntimeLaneValue(const void*) in WxRuntimeTypes.cpp
  // (Address: 0x009D2A80) - no second accessor added here to avoid a
  // duplicate Address citation for that same binary address.
};

static_assert(sizeof(wxBrushRuntimeObject) == 0xC, "wxBrushRuntimeObject size must be 0xC");

/**
 * Minimal recovered wxPen ref-data lane: the shared, ref-counted payload a
 * `wxPenRuntimeObject` points `mRefData` at once it owns a real pen.
 *
 * Offsets are read off the constructor at 0x009EB0F0, which writes every one
 * of them: `m_count` (ref count, from `wxObjectRefData`) at +0x04, `m_width`
 * at +0x08, `m_style` at +0x0C, `m_join` at +0x10, `m_cap` at +0x14, an
 * embedded `wxBitmap m_stipple` value at +0x18, `m_nbDash` at +0x24, `m_dash`
 * at +0x28, an embedded `wxColour m_colour` value at +0x2C and `m_hPen` at
 * +0x3C. `operator new(0x40u)` in the colour/width/style constructor at
 * 0x009EB8D0 confirms the total size.
 */
class wxPenRefDataRuntimeObject
{
public:
  /**
   * Address: 0x009EB0F0 (FUN_009EB0F0)
   * Mangled: ??0wxPenRefData@@QAE@XZ
   *
   * What it does:
   * Seeds a one-owner ref count and wx's default pen description - width 1,
   * `wxSOLID`, round join, round cap - and leaves the stipple bitmap, dash
   * array and native handle empty.
   */
  wxPenRefDataRuntimeObject() noexcept;

  // `wxGDIRefData : wxObjectRefData` supplies this vtable slot; a plain
  // virtual destructor reproduces it without modelling the (empty) base
  // classes separately, exactly as `wxBrushRefDataRuntimeObject` does.
  virtual ~wxPenRefDataRuntimeObject() = default;

  [[nodiscard]] std::int32_t Width() const noexcept { return mWidth; }
  [[nodiscard]] std::int32_t Style() const noexcept { return mStyle; }
  [[nodiscard]] const wxColourRuntimeObject& Colour() const noexcept { return mColour; }

  void SetWidth(const std::int32_t width) noexcept { mWidth = width; }
  void SetStyle(const std::int32_t style) noexcept { mStyle = style; }
  void SetColour(const wxColourRuntimeObject& colour) noexcept { mColour = colour; }

  // Matches `wxObject::Ref`/`wxObject::UnRef`'s intrusive counting for this
  // payload: callers share a pen by bumping the count, and release it by
  // dropping the count and freeing once nothing references it any more.
  void AddRef() noexcept { ++mRefCount; }
  [[nodiscard]] bool ReleaseRef() noexcept { return --mRefCount == 0; }

private:
  std::int32_t mRefCount = 1;                // +0x04 (wxObjectRefData::m_count)
  std::int32_t mWidth = 1;                   // +0x08
  std::int32_t mStyle = kWxStyleSolid;       // +0x0C
  std::int32_t mJoin = kWxPenJoinRound;      // +0x10
  std::int32_t mCap = kWxPenCapRound;        // +0x14
  wxBitmapRuntimeObject mStipple{};          // +0x18
  std::int32_t mDashCount = 0;               // +0x24
  void* mDashes = nullptr;                   // +0x28
  wxColourRuntimeObject mColour{};           // +0x2C
  void* mNativePenHandle = nullptr;          // +0x3C (WXHPEN)
};

static_assert(
  sizeof(wxPenRefDataRuntimeObject) == 0x40,
  "wxPenRefDataRuntimeObject size must be 0x40"
);

/**
 * Minimal recovered wxPen runtime lane.
 */
class wxPenRuntimeObject : public wxGDIObjectRuntime
{
public:
  /**
   * Address: 0x009EB2A0 (FUN_009EB2A0)
   * Mangled: ??0wxPen@@QAE@@Z
   *
   * What it does:
   * Default-constructs an empty ("null") pen: no ref-data, not visible.
   */
  wxPenRuntimeObject() noexcept;

  /**
   * Address: 0x009EB8D0 (FUN_009EB8D0)
   * Mangled: ??0wxPen@@QAE@ABVwxColour@@HH@Z
   *
   * IDA signature:
   * wxPen *__thiscall wxPen::wxPen(wxPen *this, const wxColour *col, int Width, int Style);
   *
   * What it does:
   * Allocates a fresh, single-owner `wxPenRefData` for the given
   * colour/width/style triple, matching `operator new(0x40u)` plus the
   * ref-data constructor in the binary, applies wx's Win32S dashed-pen width
   * clamp, and realizes the native pen.
   */
  wxPenRuntimeObject(
    const wxColourRuntimeObject& colour,
    std::int32_t width,
    std::int32_t style
  );

  /**
   * Address: 0x009EB2E0 (FUN_009EB2E0)
   * Mangled: ??1wxPen@@QAE@XZ
   *
   * What it does:
   * Releases ref-data ownership through the shared unref lane.
   */
  ~wxPenRuntimeObject() override;
};

static_assert(sizeof(wxPenRuntimeObject) == 0xC, "wxPenRuntimeObject size must be 0xC");
