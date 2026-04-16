#include "DName.h"

#include <new>
#include <utility>

namespace
{
constexpr std::int32_t kUnknownStatusTokenLength = 4;
constexpr char kUnknownStatusToken[] = " ?? ";
std::uint32_t gUndecoratorParseFlags = 0;
constexpr std::uint32_t kUndecoratorStripDoubleUnderscoreFlag = 0x1u;

constexpr const char* kUndecoratorTokenSpellings[] = {
  "__based(",
  "__cdecl",
  "__pascal",
  "__stdcall",
  "__thiscall",
  "__fastcall",
  "__clrcall",
  "__ptr64",
  "__restrict",
  "__unaligned",
  "",
  " Type Descriptor'",
  " Base Class Descriptor at (",
  " Base Class Array'",
  " Class Hierarchy Descriptor'",
  " Complete Object Locator'",
  " new",
  " delete",
  "=",
  ">>",
  "<<",
  "!",
  "==",
  "!=",
  "[]",
  "operator",
  "->",
  "*",
  "++",
  "--",
  "-",
  "+",
  "&",
  "->*",
  "/",
  "%",
  "<",
  "<=",
  ">",
  ">=",
  ",",
  "()",
  "~",
  "^",
  "|",
  "&&",
  "||",
  "*=",
  "+=",
  "-=",
  "/=",
  "%=",
  ">>=",
  "<<=",
  "&=",
  "|=",
  "^=",
  "`vftable'",
  "`vbtable'",
  "`vcall'",
  "`typeof'",
  "`local static guard'",
  "`string'",
  "`vbase destructor'",
  "`vector deleting destructor'",
  "`default constructor closure'",
  "`scalar deleting destructor'",
  "`vector constructor iterator'",
  "`vector destructor iterator'",
  "`vector vbase constructor iterator'",
  "`virtual displacement map'",
  "`eh vector constructor iterator'",
  "`eh vector destructor iterator'",
  "`eh vector vbase constructor iterator'",
  "`copy constructor closure'",
  "`udt returning'",
  "`EH",
  "`RTTI",
  "`local vftable'",
  "`local vftable constructor closure'",
  " new[]",
  " delete[]",
  "`omni callsig'",
  "`placement delete closure'",
  "`placement delete[] closure'",
  "`managed vector constructor iterator'",
  "`managed vector destructor iterator'",
  "`eh vector copy constructor iterator'",
  "`eh vector vbase copy constructor iterator'",
  "`dynamic initializer for '",
  "`dynamic atexit destructor for '",
  "`vector copy constructor iterator'",
  "`vector vbase copy constructor iterator'",
  "`managed vector copy constructor iterator'",
  "`local static thread guard'",
  "",
};
static_assert(
  (sizeof(kUndecoratorTokenSpellings) / sizeof(kUndecoratorTokenSpellings[0])) == 96,
  "Undecorator token spelling table size must be 96"
);

/**
 * Address: 0x00AB0FE5 (FUN_00AB0FE5, UnDecorator::UScore)
 * Mangled: ?UScore@UnDecorator@@SAPBDW4Tokens@@@Z
 *
 * What it does:
 * Returns one undecorator token spelling lane and optionally strips the
 * leading `__` prefix when parse-flag bit 0 is enabled.
 */
[[maybe_unused]] const char* ResolveUndecoratorTokenSpelling(const std::uint32_t token) noexcept
{
  const char* result = kUndecoratorTokenSpellings[token];
  if ((gUndecoratorParseFlags & kUndecoratorStripDoubleUnderscoreFlag) != 0u) {
    result += 2;
  }
  return result;
}

[[nodiscard]] constexpr DNameStatus DecodeStatusKind(
  const std::uint32_t statusWord
) noexcept
{
  return static_cast<DNameStatus>(static_cast<std::int32_t>(statusWord << 28u) >> 28);
}

using DNameHeapAllocator = void* (*)(std::size_t);

struct DNameHeapFrame
{
  DNameHeapFrame* nextFrame = nullptr;  // +0x00
  char payload[0x1000]{};               // +0x04
};
static_assert(sizeof(DNameHeapFrame) == 0x1004, "DNameHeapFrame size must be 0x1004");
static_assert(offsetof(DNameHeapFrame, nextFrame) == 0x00, "DNameHeapFrame::nextFrame offset must be 0x00");
static_assert(offsetof(DNameHeapFrame, payload) == 0x04, "DNameHeapFrame::payload offset must be 0x04");

struct DNameHeapManagerRuntimeView
{
  DNameHeapAllocator allocator = nullptr;  // +0x00
  std::uint32_t reservedWord = 0;          // +0x04
  DNameHeapFrame* firstFrame = nullptr;    // +0x08
  DNameHeapFrame* frame = nullptr;         // +0x0C
  std::uint32_t roomLeft = 0;              // +0x10

  /**
   * Address: 0x00AB0FFE (FUN_00AB0FFE, HeapManager::getMemory)
   * Mangled: ?getMemory@HeapManager@@QAEPAXIH@Z
   *
   * What it does:
   * Allocates aligned bytes from the undecorator arena, growing by 0x1004-byte
   * frames on demand, or dispatches direct heap allocations when `onHeap != 0`.
   */
  void* getMemory(std::size_t size, int onHeap) noexcept;
};
static_assert(sizeof(DNameHeapManagerRuntimeView) == 0x14, "DNameHeapManagerRuntimeView size must be 0x14");
static_assert(
  offsetof(DNameHeapManagerRuntimeView, allocator) == 0x00,
  "DNameHeapManagerRuntimeView::allocator offset must be 0x00"
);
static_assert(
  offsetof(DNameHeapManagerRuntimeView, firstFrame) == 0x08,
  "DNameHeapManagerRuntimeView::firstFrame offset must be 0x08"
);
static_assert(
  offsetof(DNameHeapManagerRuntimeView, frame) == 0x0C,
  "DNameHeapManagerRuntimeView::frame offset must be 0x0C"
);
static_assert(
  offsetof(DNameHeapManagerRuntimeView, roomLeft) == 0x10,
  "DNameHeapManagerRuntimeView::roomLeft offset must be 0x10"
);

[[nodiscard]] void* AllocateUndecoratorHeapBytes(const std::size_t byteCount) noexcept
{
  return ::operator new(byteCount, std::nothrow);
}

DNameHeapManagerRuntimeView heapManager = {
  &AllocateUndecoratorHeapBytes,
  0,
  nullptr,
  nullptr,
  0,
};

template<typename T, typename... Args>
[[nodiscard]] T* AllocateUndecoratorObject(Args&&... args) noexcept
{
  void* const storage = heapManager.getMemory(sizeof(T), 0);
  if (storage == nullptr) {
    return nullptr;
  }
  return new (storage) T(std::forward<Args>(args)...);
}

/**
 * Address: 0x00AB0FFE (FUN_00AB0FFE, HeapManager::getMemory)
 * Mangled: ?getMemory@HeapManager@@QAEPAXIH@Z
 *
 * What it does:
 * Allocates aligned bytes from the undecorator arena, growing by 0x1004-byte
 * frames when needed, and forwards direct heap requests through the allocator
 * callback lane.
 */
void* DNameHeapManagerRuntimeView::getMemory(
  const std::size_t size,
  const int onHeap
) noexcept
{
  std::size_t actualSize = (size + 7u) & ~std::size_t{7u};
  if (onHeap != 0) {
    return allocator != nullptr ? allocator(actualSize) : nullptr;
  }

  if (actualSize == 0u) {
    actualSize = 8u;
  }

  const std::uint32_t left = roomLeft;
  if (left >= actualSize) {
    roomLeft = left - static_cast<std::uint32_t>(actualSize);
  } else {
    if (actualSize > 0x1000u) {
      return nullptr;
    }

    auto* newFrame = static_cast<DNameHeapFrame*>(heapManager.getMemory(0x1004u, 1));
    if (newFrame != nullptr) {
      newFrame->nextFrame = nullptr;
    }
    if (newFrame == nullptr) {
      return nullptr;
    }

    if (frame != nullptr) {
      frame->nextFrame = newFrame;
    } else {
      firstFrame = newFrame;
    }

    frame = newFrame;
    roomLeft = static_cast<std::uint32_t>(0x1000u - actualSize);
  }

  return frame->payload + roomLeft;
}

struct DNameTextNodeRuntimeView
{
  void* vtable;           // +0x00
  DNameNode* nextNode;    // +0x04
  const char* text;       // +0x08
  std::int32_t textLength; // +0x0C
};
static_assert(sizeof(DNameTextNodeRuntimeView) == 0x10, "DNameTextNodeRuntimeView size must be 0x10");
static_assert(offsetof(DNameTextNodeRuntimeView, nextNode) == 0x04, "DNameTextNodeRuntimeView::nextNode offset must be 0x04");
static_assert(offsetof(DNameTextNodeRuntimeView, text) == 0x08, "DNameTextNodeRuntimeView::text offset must be 0x08");
static_assert(offsetof(DNameTextNodeRuntimeView, textLength) == 0x0C, "DNameTextNodeRuntimeView::textLength offset must be 0x0C");

struct DNameRuntimeView
{
  DNameNode* headNode;       // +0x00
  std::uint32_t statusWord;  // +0x04
};
static_assert(sizeof(DNameRuntimeView) == 0x08, "DNameRuntimeView size must be 0x08");
static_assert(offsetof(DNameRuntimeView, headNode) == 0x00, "DNameRuntimeView::headNode offset must be 0x00");
static_assert(offsetof(DNameRuntimeView, statusWord) == 0x04, "DNameRuntimeView::statusWord offset must be 0x04");

class DNameCharNode final : public DNameNode
{
public:
  explicit DNameCharNode(const char character) noexcept
    : character_(character)
  {
  }

  int length() override
  {
    return 1;
  }

  char getLastChar() override
  {
    return character_;
  }

  char* copyTo(char* out, const int maxChars) override
  {
    if (out == nullptr || maxChars <= 0) {
      return nullptr;
    }

    *out = character_;
    return out;
  }

private:
  char character_ = '\0';
};
static_assert(sizeof(DNameCharNode) == 0x0C, "DNameCharNode size must be 0x0C");

class DNamePcharNode final : public DNameNode
{
public:
  /**
   * Address: 0x00AB1772 (FUN_00AB1772, pcharNode::pcharNode)
   * Mangled: ??0pcharNode@@QAE@PBDH@Z
   *
   * What it does:
   * Initializes one text-node lane by resolving text length when needed,
   * allocating payload storage from the undecorator heap manager, and copying
   * source bytes with truncation-safe undecorator semantics.
   */
  DNamePcharNode(const char* text, int textLength) noexcept;

  int length() override
  {
    return textLength_;
  }

  char getLastChar() override
  {
    if (text_ == nullptr || textLength_ <= 0) {
      return '\0';
    }

    return text_[textLength_ - 1];
  }

  char* copyTo(char* out, const int maxChars) override
  {
    if (text_ == nullptr || out == nullptr || maxChars <= 0 || textLength_ <= 0) {
      return nullptr;
    }

    int charsToCopy = maxChars;
    if (charsToCopy > textLength_) {
      charsToCopy = textLength_;
    }

    for (int index = 0; index < charsToCopy; ++index) {
      const char character = text_[index];
      out[index] = character;
      if (character == '\0') {
        break;
      }
    }

    return out;
  }

private:
  char* text_ = nullptr; // +0x08
  int textLength_ = 0;   // +0x0C
};
static_assert(sizeof(DNamePcharNode) == 0x10, "DNamePcharNode size must be 0x10");

/**
 * Address: 0x00AB1772 (FUN_00AB1772, pcharNode::pcharNode)
 * Mangled: ??0pcharNode@@QAE@PBDH@Z
 *
 * What it does:
 * Initializes one text-node lane by resolving text length when needed,
 * allocating payload storage from the undecorator heap manager, and copying
 * source bytes with truncation-safe undecorator semantics.
 */
DNamePcharNode::DNamePcharNode(
  const char* const text,
  int textLength
) noexcept
{
  text_ = nullptr;
  textLength_ = 0;

  if (textLength == 0) {
    if (text == nullptr) {
      return;
    }

    while (text[textLength] != '\0') {
      ++textLength;
    }
    if (textLength == 0) {
      return;
    }
  }

  if (text == nullptr) {
    return;
  }

  auto* const storage = static_cast<char*>(heapManager.getMemory(static_cast<std::size_t>(textLength), 0));
  text_ = storage;
  textLength_ = textLength;
  if (storage == nullptr) {
    return;
  }

  const char* source = text;
  char* destination = storage;
  unsigned int remaining = static_cast<unsigned int>(textLength);
  while (remaining != 0u) {
    const char ch = *source;
    *destination = ch;
    if (ch == '\0') {
      break;
    }

    ++destination;
    ++source;
    --remaining;
  }
}

[[nodiscard]] bool IsAcceptedUndecoratorTokenChar(const unsigned char character) noexcept
{
  if (character == '_' || character == '$' || character == '<' || character == '>' || character == '-') {
    return true;
  }

  if (character >= 'a' && character <= 'z') {
    return true;
  }
  if (character >= 'A' && character <= 'Z') {
    return true;
  }
  if (character >= '0' && character <= '9') {
    return true;
  }

  if (character >= 0x80u && character <= 0xFEu) {
    return (gUndecoratorParseFlags & 0x10000u) != 0u;
  }

  return false;
}
} // namespace

/**
 * Address: 0x00AB1306 (FUN_00AB1306, DNameStatusNode::DNameStatusNode)
 * Mangled: ??0DNameStatusNode@@QAE@W4DNameStatus@@@Z
 *
 * What it does:
 * Initializes one status marker node and precomputes its printable token
 * length for `DName` string assembly.
 */
DNameStatusNode::DNameStatusNode(
  const DNameStatus status
) noexcept
  : status_(status)
  , renderedTokenLength_(status == DNameStatus::kUnknownToken ? kUnknownStatusTokenLength : 0)
{
  nextNode_ = nullptr;
}

/**
 * Address: 0x00AB132B (FUN_00AB132B, DNameStatusNode::length)
 *
 * What it does:
 * Returns the precomputed printable length for this status marker.
 */
int DNameStatusNode::length()
{
  return renderedTokenLength_;
}

/**
 * Address: 0x00AB132F (FUN_00AB132F, DNameStatusNode::getLastChar)
 *
 * What it does:
 * Returns the trailing printable character for this status marker.
 */
char DNameStatusNode::getLastChar()
{
  return status_ == DNameStatus::kUnknownToken ? ' ' : '\0';
}

/**
 * Address: 0x00AB1855 (FUN_00AB1855, DNameStatusNode::copyTo)
 *
 * What it does:
 * Copies this status marker's printable token into an output text lane.
 */
char* DNameStatusNode::copyTo(
  char* const out,
  const int maxChars
)
{
  int charsToCopy = maxChars;
  if (charsToCopy > renderedTokenLength_) {
    charsToCopy = renderedTokenLength_;
  }

  if (status_ != DNameStatus::kUnknownToken || out == nullptr || charsToCopy <= 0) {
    return nullptr;
  }

  const char* source = kUnknownStatusToken;
  char* destination = out;
  for (int remaining = charsToCopy; remaining > 0; --remaining) {
    const char ch = *source;
    *destination = ch;
    if (ch == '\0') {
      break;
    }

    ++destination;
    ++source;
  }

  return out;
}

/**
 * Address: 0x00AB12D7 (FUN_00AB12D7, pDNameNode::pDNameNode)
 *
 * What it does:
 * Initializes one pointer-node lane and clears nested values in invalid or
 * protected state.
 */
DNamePointerNode::DNamePointerNode(
  DName* value
) noexcept
  : value_(nullptr)
{
  if (value != nullptr) {
    const DNameStatus nestedStatus = DecodeStatusKind(value->statusWord_);
    if (nestedStatus != DNameStatus::kInvalid && nestedStatus != DNameStatus::kProtected) {
      value_ = value;
    }
    return;
  }

  value_ = nullptr;
}

/**
 * Address: 0x00AB181A (FUN_00AB181A)
 *
 * What it does:
 * Returns one nested `DName` length from a pointer-node lane, or 0 when the
 * nested value pointer is null.
 */
int DNamePointerNode::length()
{
  return value_ != nullptr ? value_->length() : 0;
}

/**
 * Address: 0x00AB1829 (FUN_00AB1829)
 *
 * What it does:
 * Returns one nested `DName` trailing character from a pointer-node lane, or
 * `\\0` when the nested value pointer is null.
 */
char DNamePointerNode::getLastChar()
{
  return value_ != nullptr ? value_->getLastChar() : '\0';
}

/**
 * Address: 0x00AB1838 (FUN_00AB1838)
 *
 * What it does:
 * Forwards string extraction to the nested `DName` when destination arguments
 * are non-null/non-zero.
 */
char* DNamePointerNode::copyTo(
  char* const out,
  const int maxChars
)
{
  if (value_ != nullptr && out != nullptr && maxChars != 0) {
    return value_->getString(out, maxChars);
  }

  return nullptr;
}

/**
 * Address: 0x00AB10A1 (FUN_00AB10A1, DName::DName)
 * Mangled: ??0DName@@QAE@ABV0@@Z
 *
 * What it does:
 * Copies head pointer and low-12 status lanes from another `DName`, preserving
 * this instance's upper status-word bits.
 */
DName::DName(
  const DName& other
) noexcept
{
  const std::uint32_t lowNibbleSignExtended =
    static_cast<std::uint32_t>(static_cast<std::int32_t>(other.statusWord_ << 28u) >> 28);
  statusWord_ ^= (statusWord_ ^ lowNibbleSignExtended) & 0x0Fu;

  statusWord_ = (statusWord_ & ~0x10u) | (other.statusWord_ & 0x10u);
  statusWord_ = (statusWord_ & ~0x20u) | (other.statusWord_ & 0x20u);
  statusWord_ = (statusWord_ & ~0x40u) | (other.statusWord_ & 0x40u);
  statusWord_ = (statusWord_ & ~0x80u) | (other.statusWord_ & 0x80u);

  headNode_ = other.headNode_;

  statusWord_ = (statusWord_ & ~0x100u) | (other.statusWord_ & 0x100u);
  statusWord_ = (statusWord_ & ~0x200u) | (other.statusWord_ & 0x200u);
  statusWord_ = (statusWord_ & ~0x400u) | (other.statusWord_ & 0x400u);
  statusWord_ = (statusWord_ & ~0x800u) | (other.statusWord_ & 0x800u);
}

/**
 * Address: 0x00AB1AC0 (FUN_00AB1AC0, DName::DName)
 * Mangled: ??0DName@@QAE@D@Z
 *
 * What it does:
 * Initializes one single-character token lane and leaves the chain empty when
 * `character == '\\0'`.
 */
DName::DName(const char character) noexcept
{
  headNode_ = nullptr;
  statusWord_ &= 0xFFFFF000u;
  if (character != '\0') {
    doPchar(&character, 1);
  }
}

/**
 * Address: 0x00AB1BE7 (??0DName@@QAE@_K@Z, DName::DName)
 * Mangled: ??0DName@@QAE@_K@Z
 *
 * What it does:
 * Builds one decimal token from an unsigned 64-bit input and forwards that
 * slice to `doPchar`.
 */
DName::DName(const std::uint64_t value) noexcept
{
  headNode_ = nullptr;
  statusWord_ &= 0xFFFFF000u;

  char textBuffer[32]{};
  char* writeCursor = &textBuffer[31];
  *writeCursor = '\0';

  std::uint64_t remainingValue = value;
  do {
    const std::uint64_t quotient = remainingValue / 10u;
    const std::uint64_t remainder = remainingValue % 10u;
    *--writeCursor = static_cast<char>(remainder + static_cast<std::uint64_t>('0'));
    remainingValue = quotient;
  } while (remainingValue != 0u);

  doPchar(writeCursor, static_cast<int>(&textBuffer[31] - writeCursor));
}

/**
 * Address: 0x00AB1C50 (??0DName@@QAE@_J@Z, DName::DName)
 * Mangled: ??0DName@@QAE@_J@Z
 *
 * What it does:
 * Builds one signed decimal token from a 64-bit integer and forwards that
 * slice to `doPchar`.
 */
DName::DName(const std::int64_t value) noexcept
{
  statusWord_ &= 0xFFFFF000u;
  headNode_ = nullptr;

  char textBuffer[32]{};
  char* writeCursor = &textBuffer[31];
  *writeCursor = '\0';

  bool needsSignPrefix = false;
  std::uint64_t remainingValue = static_cast<std::uint64_t>(value);
  if (value < 0) {
    needsSignPrefix = true;
    remainingValue = (~remainingValue) + 1u;
  }

  do {
    const std::uint64_t quotient = remainingValue / 10u;
    const std::uint64_t remainder = remainingValue % 10u;
    *--writeCursor = static_cast<char>(remainder + static_cast<std::uint64_t>('0'));
    remainingValue = quotient;
  } while (remainingValue != 0u);

  if (needsSignPrefix) {
    *--writeCursor = '-';
  }

  doPchar(writeCursor, static_cast<int>(&textBuffer[31] - writeCursor));
}

/**
 * Address: 0x00AB145F (FUN_00AB145F, DName::DName)
 * Mangled: ??0DName@@QAE@W4DNameStatus@@@Z
 *
 * What it does:
 * Initializes one status-backed node chain from a status lane.
 */
DName::DName(const DNameStatus status) noexcept
{
  const std::uint32_t statusByte =
    (status == DNameStatus::kInvalid || status == DNameStatus::kProtected)
      ? static_cast<std::uint32_t>(static_cast<std::uint8_t>(status))
      : 0u;
  statusWord_ ^= (statusByte ^ statusWord_) & 0x0Fu;

  DNameStatusNode* const statusNode = AllocateUndecoratorObject<DNameStatusNode>(status);
  statusWord_ &= 0xFFFFF00Fu;
  headNode_ = statusNode;
  if (statusNode == nullptr) {
    statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x3u;
  }
}

/**
 * Address: 0x00AB1409 (FUN_00AB1409, DName::DName)
 * Mangled: ??0DName@@QAE@PAV0@@Z
 *
 * What it does:
 * Builds one pointer-node lane referencing another `DName`, and updates low
 * status bits to `3` when allocation fails.
 */
DName::DName(DName* nestedName) noexcept
{
  if (nestedName != nullptr) {
    DNamePointerNode* const pointerNode = AllocateUndecoratorObject<DNamePointerNode>(nestedName);
    headNode_ = pointerNode;
    const std::uint32_t stateLowNibble = pointerNode != nullptr ? 0u : 3u;
    statusWord_ ^= (statusWord_ ^ stateLowNibble) & 0x0Fu;
  } else {
    statusWord_ &= 0xFFFFFFF0u;
    headNode_ = nullptr;
  }

  statusWord_ &= 0xFFFFF00Fu;
}

/**
 * Address: 0x00AB1645 (FUN_00AB1645, DName::operator=)
 * Mangled: ??4DName@@QAEAAV0@W4DNameStatus@@@Z
 *
 * What it does:
 * Rebinds this name to a status lane, allocating one status node for
 * non-terminal states when needed.
 */
DName& DName::operator=(const DNameStatus status) noexcept
{
  const std::uint32_t statusValue = static_cast<std::uint32_t>(static_cast<std::uint8_t>(status));
  if (status == DNameStatus::kInvalid || status == DNameStatus::kProtected) {
    headNode_ = nullptr;
    if ((statusWord_ & 0x0Fu) != 0x3u) {
      statusWord_ ^= (statusValue ^ statusWord_) & 0x0Fu;
    }
    return *this;
  }

  const DNameStatus currentStatusKind = DecodeStatusKind(statusWord_);
  if (currentStatusKind == DNameStatus::kEmpty || currentStatusKind == DNameStatus::kUnknownToken) {
    statusWord_ &= 0xFFFFF70Fu;

    DNameStatusNode* const statusNode = AllocateUndecoratorObject<DNameStatusNode>(status);
    headNode_ = statusNode;
    if (statusNode == nullptr) {
      statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x3u;
    }
  }

  return *this;
}

/**
 * Address: 0x00AB19B2 (FUN_00AB19B2)
 *
 * What it does:
 * Rebinds this name to one nested-name pointer lane when writable, or falls
 * back to protected status when nested input is absent.
 */
DName& DName::assignNestedPointer(
  DName* const nestedName
) noexcept
{
  const DNameStatus currentStatusKind = DecodeStatusKind(statusWord_);
  if (currentStatusKind != DNameStatus::kEmpty && currentStatusKind != DNameStatus::kUnknownToken) {
    return *this;
  }

  if (nestedName != nullptr) {
    statusWord_ &= 0xFFFFF70Fu;
    DNamePointerNode* const pointerNode = AllocateUndecoratorObject<DNamePointerNode>(nestedName);
    headNode_ = pointerNode;
    if (pointerNode == nullptr) {
      statusWord_ = (statusWord_ & 0xFFFFFFF3u) | 0x3u;
    }
    return *this;
  }

  return *this = DNameStatus::kProtected;
}

/**
 * Address: 0x00AB1A1A (FUN_00AB1A1A, DName::doPchar)
 * Mangled: ?doPchar@DName@@AAEXPBDH@Z
 *
 * What it does:
 * Stores one parsed text slice as either a char-node or pchar-node lane and
 * updates status bits on allocation and parse outcomes.
 */
void DName::doPchar(
  const char* const text,
  const int textLength
) noexcept
{
  const DNameStatus currentStatusKind = DecodeStatusKind(statusWord_);
  if (currentStatusKind == DNameStatus::kInvalid || currentStatusKind == DNameStatus::kProtected) {
    return;
  }

  if (headNode_ != nullptr) {
    (void)(*this = DNameStatus::kProtected);
    return;
  }

  if (text == nullptr || textLength == 0) {
    statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x1u;
    return;
  }

  DNameNode* node = nullptr;
  if (textLength == 1) {
    node = AllocateUndecoratorObject<DNameCharNode>(*text);
  } else {
    node = AllocateUndecoratorObject<DNamePcharNode>(text, textLength);
  }

  headNode_ = node;
  if (node == nullptr) {
    statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x3u;
  }
}

/**
 * Address: 0x00AB1B17 (FUN_00AB1B17, DName::DName)
 * Mangled: ??0DName@@QAE@AAPBDD@Z
 *
 * What it does:
 * Parses one token from `cursor` until `delimiter`, materializes one text
 * node lane, and updates low-nibble parse status flags.
 */
DName::DName(
  const char*& cursor,
  const char delimiter
) noexcept
{
  statusWord_ &= 0xFFFFF000u;
  std::uint32_t preservedStatusWord = statusWord_;
  headNode_ = nullptr;

  const char* const tokenBegin = cursor;
  if (tokenBegin == nullptr) {
    statusWord_ = (preservedStatusWord & 0xFFFFFFF0u) | 0x1u;
    return;
  }

  if (*cursor == '\0') {
    statusWord_ = (preservedStatusWord & 0xFFFFFFF0u) | 0x2u;
    return;
  }

  int tokenLength = 0;
  while (*cursor != '\0') {
    const unsigned char character = static_cast<unsigned char>(*cursor);
    if (character == static_cast<unsigned char>(delimiter)) {
      break;
    }

    if (!IsAcceptedUndecoratorTokenChar(character)) {
      statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x1u;
      return;
    }

    ++tokenLength;
    ++cursor;
    if (*cursor == '\0') {
      break;
    }
  }

  doPchar(tokenBegin, tokenLength);

  const char parsedTerminator = *cursor;
  if (parsedTerminator == '\0') {
    if ((statusWord_ & 0x0Fu) == 0u) {
      statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x2u;
    }
    return;
  }

  ++cursor;
  if (parsedTerminator != delimiter) {
    statusWord_ = (statusWord_ & 0xFFFFFFF0u) | 0x3u;
    headNode_ = nullptr;
    return;
  }

  statusWord_ &= 0xFFFFFFF0u;
}

/**
 * Address: 0x00AB14C0 (?isValid@DName@@QBEHXZ)
 * Mangled: ?isValid@DName@@QBEHXZ
 *
 * What it does:
 * Checks the encoded status nibble and accepts the two live states used by
 * the name-chain helpers.
 */
bool DName::isValid() const noexcept
{
  const DNameStatus statusKind = DecodeStatusKind(statusWord_);
  return statusKind == DNameStatus::kEmpty || statusKind == DNameStatus::kUnknownToken;
}

/**
 * Address: 0x00AB14EC (?isUDC@DName@@QBEHXZ)
 * Mangled: ?isUDC@DName@@QBEHXZ
 *
 * What it does:
 * Returns true when the name chain is non-empty/valid and the UDC marker bit
 * (`0x20`) is set in the status word.
 */
bool DName::isUDC() const noexcept
{
  return headNode_ != nullptr && isValid() && (statusWord_ & 0x20u) != 0u;
}

/**
 * Address: 0x00AB14D7 (?isEmpty@DName@@QBEHXZ)
 * Mangled: ?isEmpty@DName@@QBEHXZ
 *
 * What it does:
 * Returns true when the head node is null or the low status nibble is not a
 * valid/unknown-token state.
 */
bool DName::isEmpty() const noexcept
{
  return headNode_ == nullptr || !isValid();
}

/**
 * Address: 0x00AB157F (?getString@DName@@QBEPADPADH@Z)
 * Mangled: ?getString@DName@@QBEPADPADH@Z
 *
 * What it does:
 * Serializes this node chain into `out`, allocating an internal buffer when
 * `out == nullptr`, and writes a trailing NUL whenever output storage exists.
 */
char* DName::getString(
  char* out,
  const int maxChars
) const noexcept
{
  if (!isEmpty()) {
    int remainingChars = 0;
    if (out != nullptr) {
      remainingChars = maxChars;
    } else {
      remainingChars = length() + 1;
      out = remainingChars > 0
              ? static_cast<char*>(
                  heapManager.getMemory(static_cast<std::size_t>(remainingChars), 0)
                )
              : nullptr;
      if (out == nullptr) {
        return nullptr;
      }
    }

    DNameNode* node = headNode_;
    char* writeCursor = out;
    while (node != nullptr && remainingChars > 0) {
      int nodeLength = node->length();
      if (nodeLength != 0) {
        if ((remainingChars - nodeLength) < 0) {
          nodeLength = remainingChars;
        }

        if (node->copyTo(writeCursor, nodeLength) != nullptr) {
          remainingChars -= nodeLength;
          writeCursor += nodeLength;
        }
      }

      node = node->nextNode_;
    }

    *writeCursor = '\0';
  } else if (out != nullptr) {
    *out = '\0';
  }

  return out;
}

/**
 * Address: 0x00AB11B7 (??4DName@@QAEAAV0@ABV0@@Z, DName::operator=)
 *
 * What it does:
 * Copies selected status lanes and head-node pointer from `other` when this
 * instance is writable (`kEmpty` or `kUnknownToken`).
 */
DName& DName::operator=(const DName& other) noexcept
{
  const DNameStatus currentStatusKind = DecodeStatusKind(statusWord_);
  if (currentStatusKind == DNameStatus::kEmpty || currentStatusKind == DNameStatus::kUnknownToken) {
    statusWord_ = (statusWord_ & ~0x0Fu) | (other.statusWord_ & 0x0Fu);
    statusWord_ = (statusWord_ & ~0x10u) | (other.statusWord_ & 0x10u);
    statusWord_ = (statusWord_ & ~0x20u) | (other.statusWord_ & 0x20u);
    statusWord_ = (statusWord_ & ~0x40u) | (other.statusWord_ & 0x40u);
    statusWord_ = (statusWord_ & ~0x80u) | (other.statusWord_ & 0x80u);
    statusWord_ = (statusWord_ & ~0x800u) | (other.statusWord_ & 0x800u);
    headNode_ = other.headNode_;
  }

  return *this;
}

/**
 * Address: 0x00AB1610 (??_5DName@@QAEAAV0@ABV0@@Z, DName::operator|=)
 *
 * What it does:
 * Merges the low status nibble from another `DName` when this instance is not
 * in the protected status state `3`.
 */
DName& DName::operator|=(const DName& other) noexcept
{
  const DNameStatus currentStatusKind = DecodeStatusKind(statusWord_);
  if (currentStatusKind != DNameStatus::kProtected) {
    const DNameStatus otherStatusKind = DecodeStatusKind(other.statusWord_);
    if (otherStatusKind != DNameStatus::kEmpty && otherStatusKind != DNameStatus::kUnknownToken) {
      statusWord_ = (statusWord_ & ~0x0Fu) | (other.statusWord_ & 0x0Fu);
    }
  }

  return *this;
}

/**
 * Address: 0x00AB1939 (??YDName@@QAEAAV0@W4DNameStatus@@@Z, DName::operator+=)
 *
 * What it does:
 * Appends one status marker into this name chain, cloning the current head
 * lane before append when needed.
 */
DName& DName::operator+=(const DNameStatus status) noexcept
{
  if (isEmpty() || status == DNameStatus::kInvalid || status == DNameStatus::kProtected) {
    return *this = status;
  }

  DNameStatusNode* const statusNode = AllocateUndecoratorObject<DNameStatusNode>(status);
  if (statusNode != nullptr) {
    DNameNode* const clonedHead = headNode_->clone();
    headNode_ = clonedHead;
    if (clonedHead != nullptr) {
      (void)(*clonedHead += statusNode);
    }
  } else {
    headNode_ = nullptr;
  }

  if (headNode_ == nullptr) {
    statusWord_ = (statusWord_ & 0xFFFFFFF3u) | 0x3u;
  }

  return *this;
}

/**
 * Address: 0x00AB1D14 (??YDName@@QAEAAV0@ABV0@@Z, DName::operator+=)
 *
 * What it does:
 * Appends another `DName` chain or status lane into this instance with
 * clone-before-append semantics for non-empty chains.
 */
DName& DName::operator+=(const DName& other) noexcept
{
  if (other.isEmpty()) {
    return *this += DecodeStatusKind(other.statusWord_);
  }

  if (isEmpty()) {
    return *this = other;
  }

  DNameNode* const clonedHead = headNode_->clone();
  headNode_ = clonedHead;
  if (clonedHead != nullptr) {
    (void)(*clonedHead += other.headNode_);
  } else {
    statusWord_ = (statusWord_ & 0xFFFFFFF3u) | 0x3u;
  }

  return *this;
}

/**
 * Address: 0x00AB1F24 (??HDName@@QBE?AV0@ABV0@@Z, DName::operator+)
 * Mangled: ??HDName@@QBE?AV0@ABV0@@Z
 *
 * What it does:
 * Returns one value-copy of this name and then applies append/status fold
 * rules for `other` exactly as the binary control flow does.
 */
DName DName::operator+(const DName& other) const noexcept
{
  DName combined(*this);
  if (combined.isEmpty()) {
    (void)(combined = other);
  } else if (other.isEmpty()) {
    (void)(combined += DecodeStatusKind(other.statusWord_));
  } else {
    (void)(combined += other);
  }

  return combined;
}

/**
 * Address: 0x00AB220E (??HDName@@QBE?AV0@D@Z, DName::operator+)
 * Mangled: ??HDName@@QBE?AV0@D@Z
 *
 * What it does:
 * Returns one value-copy of this name and applies either assignment or append
 * of one character based on copied-empty state.
 */
DName DName::operator+(const char character) const noexcept
{
  DName combined(*this);
  if (combined.isEmpty()) {
    (void)(combined = character);
  } else {
    (void)(combined += character);
  }

  return combined;
}

/**
 * Address: 0x00AB1FA3 (??YDName@@QAEAAV0@D@Z, DName::operator+=)
 * Mangled: ??YDName@@QAEAAV0@D@Z
 *
 * What it does:
 * Appends one single-character lane when non-zero, cloning head-chain state
 * before append for non-empty destinations.
 */
DName& DName::operator+=(const char character) noexcept
{
  if (character == '\0') {
    return *this;
  }

  if (isEmpty()) {
    (void)(*this = character);
    return *this;
  }

  DNameNode* const clonedHead = headNode_->clone();
  headNode_ = clonedHead;
  if (clonedHead != nullptr) {
    DNameCharNode* const charNode = AllocateUndecoratorObject<DNameCharNode>(character);
    (void)(*clonedHead += charNode);
  } else {
    statusWord_ = (statusWord_ & 0xFFFFFFF3u) | 0x3u;
  }

  return *this;
}

/**
 * Address: 0x00AB200D (??YDName@@QAEAAV0@PBD@Z, DName::operator+=)
 * Mangled: ??YDName@@QAEAAV0@PBD@Z
 *
 * What it does:
 * Appends one text lane when source text is non-empty, cloning head-chain
 * state before append for non-empty destinations.
 */
DName& DName::operator+=(const char* const text) noexcept
{
  if (text == nullptr || *text == '\0') {
    return *this;
  }

  if (isEmpty()) {
    (void)(*this = text);
    return *this;
  }

  DNameNode* const clonedHead = headNode_->clone();
  headNode_ = clonedHead;
  if (clonedHead != nullptr) {
    DNamePcharNode* const textNode = AllocateUndecoratorObject<DNamePcharNode>(text, 0);
    (void)(*clonedHead += textNode);
  } else {
    statusWord_ = (statusWord_ & 0xFFFFFFF3u) | 0x3u;
  }

  return *this;
}

/**
 * Address: 0x00AB1E01 (FUN_00AB1E01, DName::operator=)
 * Mangled: ??4DName@@QAEAAV0@D@Z
 *
 * What it does:
 * Replaces this name with one single-character token via `doPchar`.
 */
DName& DName::operator=(const char character) noexcept
{
  statusWord_ &= 0xFFFFF70Fu;
  doPchar(&character, 1);
  return *this;
}

/**
 * Address: 0x00AB1E1D (??4DName@@QAEAAV0@PBD@Z, DName::operator=)
 * Mangled: ??4DName@@QAEAAV0@PBD@Z
 *
 * What it does:
 * Replaces this name with one text token lane by measuring source length and
 * forwarding to `doPchar`.
 */
DName& DName::operator=(const char* const text) noexcept
{
  statusWord_ &= 0xFFFFF70Fu;

  int textLength = 0;
  if (text != nullptr && *text != '\0') {
    while (text[textLength] != '\0') {
      ++textLength;
    }
  }

  doPchar(text, textLength);
  return *this;
}

/**
 * Address: 0x00AB1522 (?length@DName@@QBEHXZ)
 *
 * What it does:
 * Sums the lengths contributed by each linked name node when the name chain
 * is valid.
 */
int DName::length() const noexcept
{
  if (headNode_ == nullptr || !isValid()) {
    return 0;
  }

  int totalLength = 0;
  for (DNameNode* node = headNode_; node != nullptr; node = node->nextNode_) {
    totalLength += node->length();
  }

  return totalLength;
}

/**
 * Address: 0x00AB1547 (?getLastChar@DName@@QBEDXZ)
 *
 * What it does:
 * Returns the last non-empty character contributed by the node chain, or 0
 * when the name chain is empty/invalid.
 */
char DName::getLastChar() const noexcept
{
  if (headNode_ == nullptr || !isValid()) {
    return 0;
  }

  DNameNode* lastNonEmptyNode = nullptr;
  for (DNameNode* node = headNode_; node != nullptr; node = node->nextNode_) {
    if (node->length() != 0) {
      lastNonEmptyNode = node;
    }
  }

  if (lastNonEmptyNode == nullptr) {
    return 0;
  }

  return lastNonEmptyNode->getLastChar();
}

/**
 * Address: 0x00AB1271 (FUN_00AB1271, DNameNode::operator+=)
 *
 * What it does:
 * Appends one node chain to the tail of this node chain.
 */
DNameNode* DNameNode::operator+=(DNameNode* const node) noexcept
{
  if (node == nullptr) {
    return this;
  }

  DNameNode* tail = this;
  while (tail->nextNode_ != nullptr) {
    tail = tail->nextNode_;
  }

  tail->nextNode_ = node;
  return this;
}

/**
 * Address: 0x00AB172B (FUN_00AB172B, DNameNode::clone)
 * Mangled: ?clone@DNameNode@@QAEPAV1@XZ
 *
 * What it does:
 * Clones this node by creating one pointer-node wrapper around one shallow
 * nested `DName` lane allocated from the undecorator heap manager.
 */
DNameNode* DNameNode::clone() noexcept
{
  auto* const pointerNodeStorage =
    static_cast<DNamePointerNode*>(heapManager.getMemory(sizeof(DNamePointerNode), 0));
  if (pointerNodeStorage == nullptr) {
    return nullptr;
  }

  auto* const nestedNameStorage = static_cast<DName*>(heapManager.getMemory(sizeof(DName), 0));
  if (nestedNameStorage != nullptr) {
    auto* const nestedNameView = reinterpret_cast<DNameRuntimeView*>(nestedNameStorage);
    nestedNameView->statusWord &= 0xFFFFF000u;
    nestedNameView->headNode = this;
  }

  return new (pointerNodeStorage) DNamePointerNode(nestedNameStorage);
}

/**
 * Address: 0x00AB17E9 (FUN_00AB17E9)
 *
 * What it does:
 * Copies one pchar-node payload into `out` up to the node-text length cap and
 * the caller-provided `maxChars` cap.
 */
[[maybe_unused]] char* DNameTextNodeCopyTo(
  DNameTextNodeRuntimeView* const node,
  char* const out,
  const int maxChars
) noexcept
{
  int charsToCopy = maxChars;
  if (charsToCopy > node->textLength) {
    charsToCopy = node->textLength;
  }

  if (node->text != nullptr && out != nullptr && charsToCopy != 0) {
    const char* source = node->text;
    char* destination = out;
    unsigned int remaining = static_cast<unsigned int>(charsToCopy);
    while (remaining != 0u) {
      const char character = *source;
      *destination = character;
      if (character == '\0') {
        break;
      }

      ++destination;
      ++source;
      --remaining;
    }
    return out;
  }

  return nullptr;
}
