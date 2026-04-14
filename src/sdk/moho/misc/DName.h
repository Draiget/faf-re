#pragma once

#include <cstddef>
#include <cstdint>

class DName;

class DNameNode
{
public:
  virtual int length() = 0;
  virtual char getLastChar() = 0;
  virtual int copyTo(char* out, int maxChars) = 0;

  /**
   * Address: 0x00AB1271 (FUN_00AB1271, DNameNode::operator+=)
   *
   * What it does:
   * Appends one node chain to the tail of this node chain.
   */
  DNameNode* operator+=(DNameNode* node) noexcept;

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
  int copyTo(char* out, int maxChars) override;

private:
  DNameStatus status_ = DNameStatus::kEmpty; // +0x08
  std::int32_t renderedTokenLength_ = 0;     // +0x0C
};
static_assert(sizeof(DNameStatusNode) == 0x10, "DNameStatusNode size must be 0x10");

class DName
{
public:
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

private:
  DNameNode* headNode_ = nullptr; // +0x00
  std::uint32_t statusWord_ = 0; // +0x04
};
static_assert(sizeof(DName) == 0x08, "DName size must be 0x08");
