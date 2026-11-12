#pragma once

namespace gpg
{
  /**
   * Empty base that forbids copying, standing where the 2007 code derived from `boost::noncopyable`.
   *
   * Recovered layouts depend on it staying one empty type that every such class shares: two base subobjects of the
   * same empty type can't share an address, so MSVC pads a `DListItem`, `Listener` or `CTask` away from an earlier
   * `NonCopyable` in the same object (see `CUnitCommand.h`, `IMessageReceiver.h`). The constructor and destructor are
   * written out, as boost's are, so a class deriving from it is never trivially constructible or destructible.
   */
  class NonCopyable
  {
  protected:
    NonCopyable() {}
    ~NonCopyable() {}

  public:
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
  };
} // namespace gpg
