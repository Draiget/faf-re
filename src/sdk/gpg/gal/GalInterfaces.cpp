#include "Class.hpp"
#include "CursorContext.hpp"
#include "DrawIndexedContext.hpp"
#include "EffectMacro.hpp"
#include "Error.hpp"
#include "Head.hpp"

namespace gpg::gal
{
  namespace
  {
    void ReleaseSharedCount(boost::detail::sp_counted_base*& control) noexcept
    {
      if (control != nullptr) {
        control->release();
        control = nullptr;
      }
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
      error->runtimeMessage_.tidy(true, 0U);
    }
  } // namespace

  /**
   * Address: 0x0093F160 (FUN_0093F160)
   *
   * What it does:
   * Scalar-deleting destructor thunk owner for draw-indexed context instances.
   */
  DrawIndexedContext::~DrawIndexedContext() = default;

  /**
   * Address: 0x0093EEC0 (FUN_0093EEC0)
   *
   * What it does:
   * Releases the retained cursor-control shared-count block before object teardown.
   */
  CursorContext::~CursorContext()
  {
    ReleaseSharedCount(cursorControl_);
  }

  /**
   * Address: 0x00940950 (FUN_00940950)
   *
   * What it does:
   * Scalar-deleting destructor thunk owner for gal::Class instances.
   */
  Class::~Class() = default;

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
   * Address: 0x009404D0 (FUN_009404D0)
   * Mangled: ??0Error@gal@gpg@@QAE@@Z
   *
   * What it does:
   * Initializes file/line/message payload lanes for gal error exceptions.
   */
  Error::Error(const msvc8::string& file, const int line, const msvc8::string& message)
    : std::exception()
  {
    runtimeMessage_.assign(file, 0U, msvc8::string::npos);
    line_ = line;
    message_.assign(message, 0U, msvc8::string::npos);
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
  int Error::GetRuntimeLine() const noexcept
  {
    return line_;
  }

  /**
   * Address: 0x00940450 (FUN_00940450)
   *
   * What it does:
   * Returns the throw-site runtime text pointer from `runtimeMessage_`.
   */
  const char* Error::GetRuntimeMessage() const noexcept
  {
    return runtimeMessage_.raw_data_unsafe();
  }

  /**
   * Address: 0x00436990 (FUN_00436990)
   *
   * What it does:
   * Scalar-deleting destructor thunk owner for gal::Head instances.
   */
  Head::~Head() = default;
} // namespace gpg::gal
