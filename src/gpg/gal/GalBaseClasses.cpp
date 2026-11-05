#include "gpg/gal/GalInterfacesPrivate.h"

namespace gpg::gal
{
  /**
   * Address: 0x009044C0 (FUN_009044C0, gpg::gal::VertexFormat::VertexFormat)
   *
   * What it does:
   * Installs the base vtable and empties the stride vector (its three
   * pointers at +0x0C..+0x14). The format code is left for the backend.
   */
  VertexFormat::VertexFormat() = default;

  /**
   * Address: 0x009041B0
   *
   * What it does:
   * Reinstalls the base vtable and frees the stride vector. Both backend
   * destructors inline it (0x0094AD03 on D3D9, 0x00904225 on D3D10); this
   * out-of-line copy is for their unwind paths, and IDA never boxed it as a
   * function.
   */
  VertexFormat::~VertexFormat() = default;

  /**
   * Address: 0x00903300 (FUN_00903300)
   *
   * What it does:
   * Installs the abstract texture vtable.
   */
  Texture::Texture() = default;

  /**
   * Address: 0x009032F0 (FUN_009032F0)
   *
   * What it does:
   * Reinstalls the abstract texture vtable (`mov [ecx],0x00D43AFC; ret`). The
   * derived destructors inline it (0x00903E51, 0x0094AAD1); this out-of-line
   * body is for their unwind paths.
   */
  Texture::~Texture() = default;
namespace
{
    /**
     * Address: 0x00940940 (FUN_00940940)
     *
     * What it does:
     * Re-runs `Class` constructor side effects for ABI adapter lanes that
     * ignore constructor return values.
     */
    [[maybe_unused]] void ResetClassVtableVoidAdapter(Class* const instance) noexcept
    {
      static_cast<void>(::new (instance) Class());
    }

    /**
     * Address: 0x0093F710 (FUN_0093F710)
     * Mangled: ??1EffectMacro@gal@gpg@@UAE@XZ
     *
     * What it does:
     * Applies legacy MSVC8 `_Tidy` semantics to both `EffectMacro` string lanes.
     */
    void DestroyEffectMacroBody(EffectMacro* const effectMacro) noexcept
    {
      effectMacro->valueText_.tidy(true, 0U);
      effectMacro->keyText_.tidy(true, 0U);
    }

    /**
     * Address: 0x00940470 (FUN_00940470)
     * Mangled: ??_DError@gal@gpg@@QAEXXZ
     *
     * What it does:
     * Applies legacy MSVC8 `_Tidy` semantics to both `Error` string lanes.
     */
    void DestroyErrorBody(Error* const error) noexcept
    {
      error->message_.tidy(true, 0U);
      error->file_.tidy(true, 0U);
    }
}


  /**
   * Address: 0x0093EEA0 (FUN_0093EEA0, __imp_??0CursorContext@gal@gpg@@QAE@XZ)
   *
   * What it does:
   * Initializes a zero hotspot and an empty texture handle.
   */
  CursorContext::CursorContext()
    : hotspotX_(0)
    , hotspotY_(0)
    , texture_()
  {
  }

  /**
   * Address: 0x0093EF20 (FUN_0093EF20)
   *
   * What it does:
   * Copies the hotspot and retains the texture handle; the add-ref/release
   * pair the body shows (0x0093EF55, 0x0093EF5C) is the by-value parameter
   * being copied into the member and then destroyed.
   */
  CursorContext::CursorContext(const POINT& hotspot, const boost::shared_ptr<Texture> texture)
    : hotspotX_(hotspot.x)
    , hotspotY_(hotspot.y)
    , texture_(texture)
  {
  }

  /**
   * Address: 0x0093EE60 (FUN_0093EE60, __imp_??1CursorContext@gal@gpg@@UAE@XZ)
   * Scalar-deleting wrapper: 0x0093EEC0 (FUN_0093EEC0)
   *
   * What it does:
   * Releases the texture handle.
   */
  CursorContext::~CursorContext() = default;

  /**
   * Address: 0x00940930 (FUN_00940930)
   *
   * What it does:
   * Initializes one abstract `gal::Class` base lane by installing the class
   * vtable.
   */
  Class::Class() = default;

  /**
   * Address: 0x00940950 (FUN_00940950)
   *
   * What it does:
   * Scalar-deleting destructor thunk owner for gal::Class instances.
   */
  Class::~Class() = default;

  /**
   * Address: 0x008FA9A0 (FUN_008FA9A0)
   *
   * What it does:
   * Copy-constructs effect-macro text lanes through legacy string assign
   * semantics for key/value payloads.
   */
  EffectMacro::EffectMacro(const EffectMacro& other)
    : keyText_()
    , valueText_()
  {
    keyText_.assign(other.keyText_, 0U, fa::string::npos);
    valueText_.assign(other.valueText_, 0U, fa::string::npos);
  }

  /**
   * Address: 0x0093F8B0 (FUN_0093F8B0)
   *
   * What it does:
   * Constructs one effect-macro entry from raw C-string key/value payloads.
   */
  EffectMacro::EffectMacro(const char* const keyText, const char* const valueText)
    : keyText_()
    , valueText_()
  {
    keyText_.assign(keyText, std::strlen(keyText));
    valueText_.assign(valueText, std::strlen(valueText));
  }

  /**
   * Address: 0x008FAA20 (FUN_008FAA20)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates to `FUN_0093F710` body semantics.
   */
  EffectMacro::~EffectMacro()
  {
    DestroyEffectMacroBody(this);
  }

  /**
   * Address: 0x00940560 (FUN_00940560)
   *
   * IDA signature:
   * int __thiscall sub_940560(int this);
   *
   * What it does:
   * Initializes one `gpg::gal::Error` payload with canonical "<unknown>"
   * source/file lane and "<undefined>" message lane, used as the default
   * allocation-failure exception body in GAL backend paths. The decompiled
   * form directly built the embedded `fa::string` SSO lanes with literal
   * constants; this is the typed 1:1 equivalent.
   */
  Error::Error()
    : std::exception()
    , file_("<unknown>")
    , line_(0)
    , message_("<undefined>")
  {
  }

  /**
   * Address: 0x009404D0 (FUN_009404D0)
   * Mangled: ??0Error@gal@gpg@@QAE@@Z
   *
   * What it does:
   * Initializes file/line/message payload lanes for gal error exceptions.
   */
  Error::Error(const fa::string& file, const int line, const fa::string& message)
    : std::exception()
  {
    file_.assign(file, 0U, fa::string::npos);
    line_ = line;
    message_.assign(message, 0U, fa::string::npos);
  }

  /**
   * Address: 0x008A7B10 (FUN_008A7B10)
   *
   * What it does:
   * Owns the deleting-destructor path and delegates to `FUN_00940470` body semantics.
   */
  Error::~Error()
  {
    DestroyErrorBody(this);
  }

  /**
   * Address: 0x00940460 (FUN_00940460)
   *
   * What it does:
   * Returns the raw message data pointer (SSO buffer or heap pointer).
   */
  const char* Error::what() const noexcept
  {
    return message_.raw_data_unsafe();
  }

  /**
   * Address: 0x00940440 (FUN_00940440)
   *
   * What it does:
   * Returns the stored source line captured by the constructor payload.
   */
  int Error::GetLine() const noexcept
  {
    return line_;
  }

  /**
   * Address: 0x00940450 (FUN_00940450)
   *
   * What it does:
   * Returns the raw source-file string pointer stored in `file_`.
   */
  const char* Error::GetFile() const noexcept
  {
    return file_.raw_data_unsafe();
  }

  /**
   * Address: 0x008E6D80 (FUN_008E6D80, gpg::gal::Head::Head)
   *
   * What it does:
   * Initializes one GAL head descriptor and zeroes scalar/runtime vector
   * lanes.
   */
  Head::Head() = default;

  /**
   * Address: 0x008E6E00 (FUN_008E6E00, gpg::gal::Head::Head)
   *
   * IDA signature:
   * gpg::gal::Head *__thiscall gpg::gal::Head::Head(
   *     gpg::gal::Head *this@<ecx>,
   *     void *handle, void *window, char windowed,
   *     unsigned int width, unsigned int height,
   *     unsigned int fps);
   *
   * What it does:
   * Initializes one GAL head descriptor with caller-provided adapter handle,
   * window handle, windowed flag, pixel dimensions, and frames-per-second,
   * while zeroing antialiasing lanes and default-initializing the name and
   * all nested vector lanes (sample options, adapter modes, valid-format
   * arrays).
   */
  Head::Head(
    void* const handle,
    void* const window,
    const bool windowed,
    const std::uint32_t width,
    const std::uint32_t height,
    const std::uint32_t framesPerSecondValue)
  {
    mHandle = handle;
    mWindow = window;
    mWindowed = windowed;
    mWidth = width;
    mHeight = height;
    framesPerSecond = framesPerSecondValue;
    antialiasingHigh = 0U;
    antialiasingLow = 0U;
  }

  /**
   * Address: 0x004368B0 (FUN_004368B0)
   *
   * What it does:
   * Copy-constructs one GAL head descriptor by default-initializing this lane
   * and applying `operator=` to copy owned payloads.
   */
  Head::Head(const Head& other)
    : Head()
  {
    *this = other;
  }

  /**
   * Address: 0x008D7310 (FUN_008D7310)
   *
   * What it does:
   * Copies one GAL head descriptor lane in-place, including owned text and
   * nested vector payloads, without altering the vftable.
   */
  Head& Head::operator=(const Head& other)
  {
    mHandle = other.mHandle;
    mWindow = other.mWindow;
    mWindowed = other.mWindowed;
    mWidth = other.mWidth;
    mHeight = other.mHeight;
    framesPerSecond = other.framesPerSecond;
    antialiasingHigh = other.antialiasingHigh;
    antialiasingLow = other.antialiasingLow;
    name.assign(other.name, 0U, fa::string::npos);
    mStrs = other.mStrs;
    adapterModes = other.adapterModes;
    validFormats2 = other.validFormats2;
    validFormats1 = other.validFormats1;
    return *this;
  }

  /**
   * Address: 0x008E68E0 (FUN_008E68E0, gpg::gal::Head::HasCapability1)
   *
   * IDA signature:
   * bool __thiscall gpg::gal::Head::HasCapability1(gpg::gal::Head *this, int a2);
   *
   * What it does:
   * Linear scan of the first valid-format list for `format`.
   */
  bool Head::HasCapability1(const std::int32_t format) const
  {
    return std::ranges::find(validFormats1, format) != validFormats1.end();
  }

  /**
   * Address: 0x008E6910 (FUN_008E6910, gpg::gal::Head::HasCapability2)
   *
   * IDA signature:
   * bool __thiscall gpg::gal::Head::HasCapability2(gpg::gal::Head *this, int a2);
   *
   * What it does:
   * Linear scan of the second valid-format list for `format`.
   */
  bool Head::HasCapability2(const std::int32_t format) const
  {
    return std::ranges::find(validFormats2, format) != validFormats2.end();
  }

  /**
   * Address: 0x008E6EA0 (FUN_008E6EA0, gpg::gal::Head::~Head)
   * Address: 0x00436990 (FUN_00436990)
   *
   * What it does:
   * Nothing of its own. Everything 0x008E6EA0 runs after the vftable store is
   * a member destructor MSVC emits in reverse declaration order: the three
   * `fa::vector` `_Tidy`s at `+0x74`, `+0x64` and `+0x54`, then
   * `~vector<HeadSampleOption>` at `+0x40` (its `destroy_range` at 0x00437850
   * tidies each element's 0x1C label string, then the block is freed), then
   * `~string` at `+0x24`. `0x00436990` is the scalar-deleting thunk that
   * dispatches here and conditionally frees `this`.
   */
  Head::~Head() = default;
}

