#include "DName.h"

namespace
{
constexpr std::int32_t kUnknownStatusTokenLength = 4;
constexpr char kUnknownStatusToken[] = " ?? ";

[[nodiscard]] constexpr DNameStatus DecodeStatusKind(
  const std::uint32_t statusWord
) noexcept
{
  return static_cast<DNameStatus>(static_cast<std::int32_t>(statusWord << 28u) >> 28);
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
int DNameStatusNode::copyTo(
  char* const out,
  const int maxChars
)
{
  int charsToCopy = maxChars;
  if (charsToCopy > renderedTokenLength_) {
    charsToCopy = renderedTokenLength_;
  }

  if (status_ != DNameStatus::kUnknownToken || out == nullptr || charsToCopy <= 0) {
    return 0;
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

  return 1;
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
