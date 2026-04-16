#pragma once

#include <cstddef>
#include <cstdint>

class DName;

class DNameNode
{
public:
  virtual int length() = 0;
  virtual char getLastChar() = 0;
  virtual char* copyTo(char* out, int maxChars) = 0;

  /**
   * Address: 0x00AB1271 (FUN_00AB1271, DNameNode::operator+=)
   *
   * What it does:
   * Appends one node chain to the tail of this node chain.
   */
  DNameNode* operator+=(DNameNode* node) noexcept;

  /**
   * Address: 0x00AB172B (FUN_00AB172B, DNameNode::clone)
   * Mangled: ?clone@DNameNode@@QAEPAV1@XZ
   *
   * What it does:
   * Clones this node by building one pointer-node wrapper over one shallow
   * nested `DName` lane allocated from the undecorator heap manager.
   */
  DNameNode* clone() noexcept;

private:
  friend class DName;
  friend class DNameStatusNode;

  DNameNode* nextNode_ = nullptr; // +0x04
};
static_assert(sizeof(DNameNode) == 0x08, "DNameNode size must be 0x08");

enum class DNameStatus : std::int32_t
{
  kEmpty = 0,
  kInvalid = 1,
  kUnknownToken = 2,
  kProtected = 3,
};

class DNameStatusNode final : public DNameNode
{
public:
  /**
   * Address: 0x00AB1306 (FUN_00AB1306, DNameStatusNode::DNameStatusNode)
   * Mangled: ??0DNameStatusNode@@QAE@W4DNameStatus@@@Z
   *
   * What it does:
   * Initializes one status marker node and precomputes its printable token
   * length for `DName` string assembly.
   */
  explicit DNameStatusNode(DNameStatus status) noexcept;

  /**
   * Address: 0x00AB132B (FUN_00AB132B, DNameStatusNode::length)
   *
   * What it does:
   * Returns the precomputed printable length for this status marker.
   */
  int length() override;

  /**
   * Address: 0x00AB132F (FUN_00AB132F, DNameStatusNode::getLastChar)
   *
   * What it does:
   * Returns the trailing printable character for this status marker.
   */
  char getLastChar() override;

  /**
   * Address: 0x00AB1855 (FUN_00AB1855, DNameStatusNode::copyTo)
   *
   * What it does:
   * Copies this status marker's printable token into an output text lane.
   */
  char* copyTo(char* out, int maxChars) override;

private:
  DNameStatus status_ = DNameStatus::kEmpty; // +0x08
  std::int32_t renderedTokenLength_ = 0;     // +0x0C
};
static_assert(sizeof(DNameStatusNode) == 0x10, "DNameStatusNode size must be 0x10");

class DNamePointerNode final : public DNameNode
{
public:
  /**
   * Address: 0x00AB12D7 (FUN_00AB12D7, pDNameNode::pDNameNode)
   *
   * What it does:
   * Initializes one pointer-node lane and drops nested names in invalid or
   * protected state.
   */
  explicit DNamePointerNode(DName* value) noexcept;

  /**
   * Address: 0x00AB181A (FUN_00AB181A)
   *
   * What it does:
   * Returns nested-name length when a nested value is present.
   */
  int length() override;

  /**
   * Address: 0x00AB1829 (FUN_00AB1829)
   *
   * What it does:
   * Returns the nested-name trailing character when present.
   */
  char getLastChar() override;

  /**
   * Address: 0x00AB1838 (FUN_00AB1838)
   *
   * What it does:
   * Forwards text extraction to nested `DName::getString` when arguments are
   * valid; otherwise returns `nullptr`.
   */
  char* copyTo(char* out, int maxChars) override;

private:
  DName* value_ = nullptr; // +0x08
};
static_assert(sizeof(DNamePointerNode) == 0x0C, "DNamePointerNode size must be 0x0C");

class DName
{
public:
  DName() noexcept = default;

  /**
   * Address: 0x00AB10A1 (FUN_00AB10A1, DName::DName)
   * Mangled: ??0DName@@QAE@ABV0@@Z
   *
   * What it does:
   * Copies pointer head plus low-status flag lanes from another `DName`,
   * preserving this instance's upper status word bits.
   */
  DName(const DName& other) noexcept;

  /**
   * Address: 0x00AB1AC0 (FUN_00AB1AC0, DName::DName)
   * Mangled: ??0DName@@QAE@D@Z
   *
   * What it does:
   * Initializes one single-character name lane; leaves the chain empty when
   * `character == '\\0'`.
   */
  explicit DName(char character) noexcept;

  /**
   * Address: 0x00AB1BE7 (??0DName@@QAE@_K@Z, DName::DName)
   * Mangled: ??0DName@@QAE@_K@Z
   *
   * What it does:
   * Builds one decimal text token from an unsigned 64-bit value and forwards
   * that token to `doPchar`.
   */
  explicit DName(std::uint64_t value) noexcept;

  /**
   * Address: 0x00AB1C50 (??0DName@@QAE@_J@Z, DName::DName)
   * Mangled: ??0DName@@QAE@_J@Z
   *
   * What it does:
   * Builds one decimal text token from a signed 64-bit value (including sign
   * handling) and forwards that token to `doPchar`.
   */
  explicit DName(std::int64_t value) noexcept;

  /**
   * Address: 0x00AB145F (FUN_00AB145F, DName::DName)
   * Mangled: ??0DName@@QAE@W4DNameStatus@@@Z
   *
   * What it does:
   * Initializes one status-backed node chain from a status lane.
   */
  explicit DName(DNameStatus status) noexcept;

  /**
   * Address: 0x00AB1409 (FUN_00AB1409, DName::DName)
   * Mangled: ??0DName@@QAE@PAV0@@Z
   *
   * What it does:
   * Builds one pointer-node lane that references another `DName`.
   */
  explicit DName(DName* nestedName) noexcept;

  /**
   * Address: 0x00AB1B17 (FUN_00AB1B17, DName::DName)
   * Mangled: ??0DName@@QAE@AAPBDD@Z
   *
   * What it does:
   * Parses one token from `cursor` until `delimiter`, materializes one text
   * node lane, and updates low-nibble parse status flags.
   */
  DName(const char*& cursor, char delimiter) noexcept;

  /**
   * Address: 0x00AB14C0 (?isValid@DName@@QBEHXZ)
   * Mangled: ?isValid@DName@@QBEHXZ
   *
   * What it does:
   * Checks the encoded status nibble and accepts the two live states used by
   * the name-chain helpers.
   */
  [[nodiscard]] bool isValid() const noexcept;

  /**
   * Address: 0x00AB14EC (?isUDC@DName@@QBEHXZ)
   * Mangled: ?isUDC@DName@@QBEHXZ
   *
   * What it does:
   * Returns true when the name chain is non-empty/valid and the UDC marker bit
   * (`0x20`) is set in the status word.
   */
  [[nodiscard]] bool isUDC() const noexcept;

  /**
   * Address: 0x00AB14D7 (?isEmpty@DName@@QBEHXZ)
   * Mangled: ?isEmpty@DName@@QBEHXZ
   *
   * What it does:
   * Returns true when this name has no head node or is currently invalid.
   */
  [[nodiscard]] bool isEmpty() const noexcept;

  /**
   * Address: 0x00AB11B7 (??4DName@@QAEAAV0@ABV0@@Z, DName::operator=)
   *
   * What it does:
   * Copies node-head and selected status bits from `other` when this name is
   * currently in a writable state (`kEmpty` or `kUnknownToken`).
   */
  DName& operator=(const DName& other) noexcept;

  /**
   * Address: 0x00AB1610 (??_5DName@@QAEAAV0@ABV0@@Z, DName::operator|=)
   *
   * What it does:
   * Merges the low status nibble from another `DName` when this instance is
   * not in the protected status state `3`.
   */
  DName& operator|=(const DName& other) noexcept;

  /**
   * Address: 0x00AB1939 (??YDName@@QAEAAV0@W4DNameStatus@@@Z, DName::operator+=)
   * Mangled: ??YDName@@QAEAAV0@W4DNameStatus@@@Z
   *
   * What it does:
   * Appends one status-node lane onto this name chain, or rewrites status
   * directly when the destination is empty or terminal.
   */
  DName& operator+=(DNameStatus status) noexcept;

  /**
   * Address: 0x00AB1D14 (??YDName@@QAEAAV0@ABV0@@Z, DName::operator+=)
   * Mangled: ??YDName@@QAEAAV0@ABV0@@Z
   *
   * What it does:
   * Appends another `DName` lane chain, folding empty-status-only sources into
   * status append logic.
   */
  DName& operator+=(const DName& other) noexcept;

  /**
   * Address: 0x00AB1F24 (??HDName@@QBE?AV0@ABV0@@Z, DName::operator+)
   * Mangled: ??HDName@@QBE?AV0@ABV0@@Z
   *
   * What it does:
   * Returns one copy of this name with `other` appended; empty-source cases
   * preserve original status-folding semantics.
   */
  DName operator+(const DName& other) const noexcept;

  /**
   * Address: 0x00AB220E (??HDName@@QBE?AV0@D@Z, DName::operator+)
   * Mangled: ??HDName@@QBE?AV0@D@Z
   *
   * What it does:
   * Returns one copy of this name with one character appended/assigned
   * depending on whether the copied destination is empty.
   */
  DName operator+(char character) const noexcept;

  /**
   * Address: 0x00AB1FA3 (??YDName@@QAEAAV0@D@Z, DName::operator+=)
   * Mangled: ??YDName@@QAEAAV0@D@Z
   *
   * What it does:
   * Appends one single-character lane when non-zero, cloning head-chain state
   * before append for non-empty destinations.
   */
  DName& operator+=(char character) noexcept;

  /**
   * Address: 0x00AB200D (??YDName@@QAEAAV0@PBD@Z, DName::operator+=)
   * Mangled: ??YDName@@QAEAAV0@PBD@Z
   *
   * What it does:
   * Appends one text lane when source text is non-empty, cloning head-chain
   * state before append for non-empty destinations.
   */
  DName& operator+=(const char* text) noexcept;

  /**
   * Address: 0x00AB1E01 (FUN_00AB1E01, DName::operator=)
   * Mangled: ??4DName@@QAEAAV0@D@Z
   *
   * What it does:
   * Replaces this name with one single-character token via `doPchar`.
   */
  DName& operator=(char character) noexcept;

  /**
   * Address: 0x00AB1E1D (??4DName@@QAEAAV0@PBD@Z, DName::operator=)
   * Mangled: ??4DName@@QAEAAV0@PBD@Z
   *
   * What it does:
   * Replaces this name with one text token lane by measuring source length and
   * forwarding to `doPchar`.
   */
  DName& operator=(const char* text) noexcept;

  /**
   * Address: 0x00AB1645 (FUN_00AB1645, DName::operator=)
   * Mangled: ??4DName@@QAEAAV0@W4DNameStatus@@@Z
   *
   * What it does:
   * Rebinds this name to a status lane, allocating one status node for
   * non-terminal states when needed.
   */
  DName& operator=(DNameStatus status) noexcept;

  /**
   * Address: 0x00AB1522 (?length@DName@@QBEHXZ)
   *
   * What it does:
   * Sums the lengths contributed by each linked name node when the name chain
   * is valid.
   */
  [[nodiscard]] int length() const noexcept;

  /**
   * Address: 0x00AB1547 (?getLastChar@DName@@QBEDXZ)
   *
   * What it does:
   * Returns the last non-empty character contributed by the node chain, or 0
   * when the name chain is empty/invalid.
   */
  [[nodiscard]] char getLastChar() const noexcept;

  /**
   * Address: 0x00AB157F (?getString@DName@@QBEPADPADH@Z)
   * Mangled: ?getString@DName@@QBEPADPADH@Z
   *
   * What it does:
   * Serializes the node chain into `out` (or allocates one buffer when
   * `out == nullptr`) and always NUL-terminates when a destination exists.
   */
  char* getString(char* out, int maxChars) const noexcept;

private:
  friend class DNamePointerNode;
  friend class DNameNode;

  /**
   * Address: 0x00AB19B2 (FUN_00AB19B2)
   *
   * What it does:
   * Rebinds this name to one nested-name pointer lane when writable, or
   * transitions to protected status on null nested input.
   */
  DName& assignNestedPointer(DName* nestedName) noexcept;

  /**
   * Address: 0x00AB1A1A (FUN_00AB1A1A, DName::doPchar)
   * Mangled: ?doPchar@DName@@AAEXPBDH@Z
   *
   * What it does:
   * Stores one parsed text slice as either a char-node or pchar-node lane and
   * updates status bits on allocation and parse outcomes.
   */
  void doPchar(const char* text, int textLength) noexcept;

  DNameNode* headNode_ = nullptr; // +0x00
  std::uint32_t statusWord_ = 0; // +0x04
};
static_assert(sizeof(DName) == 0x08, "DName size must be 0x08");
