#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class UserUnit;

  /** One entry of a user command-queue link run; only ever handled by pointer. */
  struct UserCommandQueueEntry;

  /** One issue-queue helper block; only ever handled by pointer. */
  struct UserManagerHelperEntry;

  /**
   * The inline-capable pointer run the manager keeps its command-queue links
   * in: `{begin, end, capacityEnd, inlineBase}`, matching the fastvector shape
   * the binary resizes through FUN_008B7590.
   */
  struct UserCommandQueueLinkVector
  {
    UserCommandQueueEntry* begin;       // +0x00
    UserCommandQueueEntry* end;         // +0x04
    UserCommandQueueEntry* capacityEnd; // +0x08
    UserCommandQueueEntry** inlineBase; // +0x0C
  };
  static_assert(sizeof(UserCommandQueueLinkVector) == 0x10, "UserCommandQueueLinkVector size must be 0x10");

  /** The manager's pending-issue ring: block table, block count, start, size. */
  struct UserManagerIssueQueue
  {
    std::uint32_t pad_00;            // +0x00
    UserManagerHelperEntry** blocks; // +0x04
    std::uint32_t blockCount;        // +0x08
    std::uint32_t startOffset;       // +0x0C
    std::uint32_t size;              // +0x10
    std::uint32_t pad_14;            // +0x14
  };
  static_assert(offsetof(UserManagerIssueQueue, blocks) == 0x04, "UserManagerIssueQueue::blocks offset must be 0x04");
  static_assert(
    offsetof(UserManagerIssueQueue, blockCount) == 0x08, "UserManagerIssueQueue::blockCount offset must be 0x08"
  );
  static_assert(
    offsetof(UserManagerIssueQueue, startOffset) == 0x0C, "UserManagerIssueQueue::startOffset offset must be 0x0C"
  );
  static_assert(offsetof(UserManagerIssueQueue, size) == 0x10, "UserManagerIssueQueue::size offset must be 0x10");
  static_assert(sizeof(UserManagerIssueQueue) == 0x18, "UserManagerIssueQueue size must be 0x18");

  /**
   * The per-unit command queue hanging off `UserUnit::mManager` and
   * `UserUnit::mFactoryManager` (0x3C8 / 0x3CC).
   *
   * The class name comes from the mangled signature of the accessors that
   * hand it out - `?GetCommandQueue@UserEntity@Moho@@UAEPAVUserCommandQueue@2@XZ`
   * returns exactly this object, and `UserUnit`'s override of that slot
   * (FUN_008BF150 / FUN_008BF130) returns `mManager`. There is no vtable: the
   * first word is the owning unit, not a vptr.
   *
   * Layout evidence: the `UserUnit` constructor (FUN_008BF420 at 0x008BF612)
   * stands one up field by field - owner at +0x00, both link runs seeded onto
   * their own inline storage, the issue ring's four words zeroed, and the
   * dirty flag cleared. FUN_008B6C50 then resizes `primaryLinks` through
   * FUN_008B7590, walks `resolvedLinks` and raises `resolvedLinksDirty`.
   */
  struct UserCommandQueue
  {
    UserUnit* ownerUnit;                      // +0x00
    std::uint8_t pad_0004_0008[0x04];
    UserCommandQueueLinkVector primaryLinks;  // +0x08
    /// Two-entry small-buffer store `primaryLinks` starts out pointing at.
    /// While the run lives here the first word doubles as the saved inline
    /// capacity end (FUN_008B7CC0 stashes it there on the way to the heap).
    std::uint8_t primaryInlineStorage[0x10];  // +0x18
    UserManagerIssueQueue issueQueue;         // +0x28
    UserCommandQueueLinkVector resolvedLinks; // +0x40
    /// The matching two-entry small-buffer store for `resolvedLinks`.
    std::uint8_t resolvedInlineStorage[0x10]; // +0x50
    std::uint8_t resolvedLinksDirty;          // +0x60
    std::uint8_t pad_0061_0068[0x07];
  };
  static_assert(offsetof(UserCommandQueue, primaryLinks) == 0x08, "UserCommandQueue::primaryLinks offset must be 0x08");
  static_assert(
    offsetof(UserCommandQueue, primaryInlineStorage) == 0x18,
    "UserCommandQueue::primaryInlineStorage offset must be 0x18"
  );
  static_assert(offsetof(UserCommandQueue, issueQueue) == 0x28, "UserCommandQueue::issueQueue offset must be 0x28");
  static_assert(offsetof(UserCommandQueue, resolvedLinks) == 0x40, "UserCommandQueue::resolvedLinks offset must be 0x40");
  static_assert(
    offsetof(UserCommandQueue, resolvedInlineStorage) == 0x50,
    "UserCommandQueue::resolvedInlineStorage offset must be 0x50"
  );
  static_assert(
    offsetof(UserCommandQueue, resolvedLinksDirty) == 0x60, "UserCommandQueue::resolvedLinksDirty offset must be 0x60"
  );
  static_assert(sizeof(UserCommandQueue) == 0x68, "UserCommandQueue size must be 0x68");
} // namespace moho
