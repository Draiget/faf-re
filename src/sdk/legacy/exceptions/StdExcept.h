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
   * The message-carrying layer of MSVC8's `<stdexcept>`, which unlike the
   * modern one keeps the text in an embedded `string` rather than a
   * refcounted handle. That is why this has to exist at all: anything
   * deriving from the modern `std::runtime_error` is 0x1C bytes too short,
   * and its own members land at the wrong offsets.
   *
   * MSVC8 declares `logic_error` and `runtime_error` as two classes with
   * *identical* contents, and the compiler duly emitted both. The two
   * constructors in the image are the same 28 instructions in the same
   * order, differing in exactly two immediates - the vtable and the EH
   * table:
   *
   *     0x00405130  runtime_error   mov dword ptr [esi], 0xD4159C
   *     0x004084E0  logic_error     mov dword ptr [esi], 0xD41590
   *
   *     call 0xA821B0             ; exception::exception()
   *     lea  ecx, [esi+0xC]       ; the embedded string
   *     mov  dword ptr [ecx+0x14], 0    ; _Mysize
   *     mov  dword ptr [ecx+0x18], 0xF  ; _Myres, the SSO capacity
   *     mov  byte  ptr [ecx+4], 0       ; _Bx._Buf[0]
   *     push -1 / push 0 / push <arg>
   *     call 0x4056B0             ; string::assign(other, 0, npos)
   *     ret  4
   *
   * They are separate addresses rather than ICF-folded precisely because of
   * those two immediates. So this is one definition that the compiler emits
   * twice, which is what a template is - writing the two bodies out by hand
   * would be transcribing the compiler's output instead of its input. One
   * instantiation per tag regenerates exactly those two classes, each with
   * its own vtable.
   *
   * Base at +0x00, string at +0x0C, 0x0C + 0x1C = 0x28.
   */
  template <class TTag>
  class message_exception : public exception
  {
  public:
    /**
     * Address: 0x00405130 (FUN_00405130, std::runtime_error::runtime_error)
     * Address: 0x004084E0 (FUN_004084E0, std::logic_error::logic_error)
     *
     * What it does:
     * Runs the `exception` base constructor, then copies the message into
     * the embedded string. The binary open-codes that copy as an
     * empty-string initialization followed by `string::assign(m, 0, npos)`,
     * which is what MSVC emits for a `string` member-initializer.
     */
    explicit message_exception(const string& message) noexcept
      : exception()
      , mStr(message)
    {
    }

    ~message_exception() override = default;

    /**
     * What it does:
     * Answers from the embedded string rather than the base's borrowed
     * pointer, which is the whole point of this layer.
     */
    [[nodiscard]] const char* what() const noexcept override
    {
      return mStr.c_str();
    }

  private:
    string mStr; // +0x0C the message, by value
  };

  /// Tags that give each instantiation its own type and vtable, matching the
  /// two classes MSVC8 declares separately.
  struct logic_error_tag
  {
  };

  struct runtime_error_tag
  {
  };

  using logic_error = message_exception<logic_error_tag>;
  using runtime_error = message_exception<runtime_error_tag>;

  // mStr is the only member, so the sizes pin it to +0x0C between them -
  // the displacement both constructors use (`lea ecx, [esi+0xCh]`). An
  // offsetof would say it more directly but cannot reach a private member.
  static_assert(sizeof(runtime_error) == sizeof(exception) + sizeof(string),
                "msvc8::runtime_error must be its base plus exactly one string");
  static_assert(sizeof(runtime_error) == 0x28, "msvc8::runtime_error size must be 0x28");
  static_assert(sizeof(logic_error) == 0x28, "msvc8::logic_error size must be 0x28");

  // The six leaves MSVC8 derives from these two - length_error, out_of_range,
  // invalid_argument and domain_error from logic_error, range_error and
  // overflow_error from runtime_error - add no members, only identity. They
  // are not declared here because nothing has been migrated onto them yet;
  // src/sdk still throws the modern std:: ones at ~140 sites, and moving
  // those is its own pass.
} // namespace msvc8
