#pragma once

#include <cstddef>

#include "legacy/containers/String.h" // msvc8::string

namespace msvc8
{
  /**
   * MSVC8's `std::exception`, which is not the modern one.
   *
   * `std::exception::exception()` (0x00A821B0) is the whole layout in five
   * instructions:
   *
   *     mov  eax, ecx
   *     and  dword ptr [eax+4], 0     ; mWhat  = nullptr
   *     and  dword ptr [eax+8], 0     ; mDoFree = 0
   *     mov  dword ptr [eax], 0xD72A44 ; vptr
   *     ret
   *
   * so vptr at +0x00 and the two members at +0x04/+0x08, 0x0C in total. The
   * `mDoFree` flag is what tells the CRT whether `mWhat` is a borrowed
   * literal or a buffer this object owns.
   *
   * Only the default constructor is declared here. The CRT's other two - the
   * one that copies the message and sets `mDoFree`, and the borrowing
   * `(const char*&, int)` overload - have no caller in the recovered tree:
   * `runtime_error` keeps its text in its own string and leaves `mWhat`
   * null, which is the only form anything here constructs. Declaring them
   * would mean inventing bodies, so they are left out rather than guessed.
   * That also makes the copy trivially safe, since `mDoFree` is never set.
   */
  class exception
  {
  public:
    /// Address: 0x00A821B0 (FUN_00A821B0, std::exception::exception)
    exception() noexcept = default;

    exception(const exception& other) noexcept = default;
    exception& operator=(const exception& other) noexcept = default;
    virtual ~exception();

    [[nodiscard]] virtual const char* what() const noexcept;

  private:
    const char* mWhat = nullptr; // +0x04 message, borrowed or owned
    int mDoFree = 0;             // +0x08 non-zero when mWhat must be freed
  };

  static_assert(sizeof(exception) == 0x0C, "msvc8::exception size must be 0x0C");

  /**
   * MSVC8's `std::runtime_error`, which unlike the modern one carries the
   * message in an embedded `string` rather than a refcounted handle. That is
   * the whole reason this type has to exist here: anything deriving from the
   * modern `std::runtime_error` is 0x1C bytes too short, and its own members
   * land at the wrong offsets.
   *
   * `std::runtime_error::runtime_error(const string&)` (0x00405130) is:
   *
   *     call 0xA821B0             ; exception::exception()
   *     lea  ecx, [esi+0xC]       ; the embedded string
   *     mov  dword ptr [esi], 0xD4159C
   *     mov  dword ptr [ecx+0x14], 0    ; _Mysize
   *     mov  dword ptr [ecx+0x18], 0xF  ; _Myres, the SSO capacity
   *     mov  byte  ptr [ecx+4], 0       ; _Bx._Buf[0]
   *     push -1 / push 0 / push <arg>
   *     call 0x4056B0             ; string::assign(other, 0, npos)
   *     ret  4
   *
   * - the base at +0x00, the string at +0x0C, and 0x0C + 0x1C = 0x28 total.
   */
  class runtime_error : public exception
  {
  public:
    /// Address: 0x00405130 (FUN_00405130, std::runtime_error::runtime_error)
    explicit runtime_error(const string& message) noexcept;

    ~runtime_error() override;

    [[nodiscard]] const char* what() const noexcept override;

  private:
    string mStr; // +0x0C the message, by value
  };

  // mStr is the only member, so the two sizes pin it to +0x0C between them -
  // which is the displacement the constructor at 0x00405130 uses
  // (`lea ecx, [esi+0xCh]`). An offsetof would say it more directly but
  // cannot reach a private member.
  static_assert(sizeof(runtime_error) == sizeof(exception) + sizeof(string),
                "msvc8::runtime_error must be its base plus exactly one string");
  static_assert(sizeof(runtime_error) == 0x28, "msvc8::runtime_error size must be 0x28");
} // namespace msvc8
