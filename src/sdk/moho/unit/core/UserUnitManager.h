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
   * The per-unit command manager hanging off `UserUnit::mManager` and
   * `UserUnit::mFactoryManager` (0x3C8 / 0x3CC).
   *
   * Layout evidence: FUN_008B6C50 resizes `primaryLinks` at +0x08 through
   * FUN_008B7590, walks the 8-byte `resolvedLinks` run at +0x40..+0x44 with its
   * capacity/inline lanes at +0x48/+0x4C, and raises `resolvedLinksDirty` at
   * +0x60. FUN_008B6DE0 (`add`) and FUN_008B6E60 (`reset`) agree.
   */
  struct UserUnitManager
  {
    UserUnit* ownerUnit;                      // +0x00
    std::uint8_t pad_0004_0008[0x04];
    UserCommandQueueLinkVector primaryLinks;  // +0x08
    std::uint8_t pad_0018_0028[0x10];
    UserManagerIssueQueue issueQueue;         // +0x28
    UserCommandQueueLinkVector resolvedLinks; // +0x40
    std::uint8_t pad_0050_0060[0x10];
    std::uint8_t resolvedLinksDirty;          // +0x60
    std::uint8_t pad_0061_0068[0x07];
  };
  static_assert(offsetof(UserUnitManager, primaryLinks) == 0x08, "UserUnitManager::primaryLinks offset must be 0x08");
  static_assert(offsetof(UserUnitManager, issueQueue) == 0x28, "UserUnitManager::issueQueue offset must be 0x28");
  static_assert(offsetof(UserUnitManager, resolvedLinks) == 0x40, "UserUnitManager::resolvedLinks offset must be 0x40");
  static_assert(
    offsetof(UserUnitManager, resolvedLinksDirty) == 0x60, "UserUnitManager::resolvedLinksDirty offset must be 0x60"
  );
  static_assert(sizeof(UserUnitManager) == 0x68, "UserUnitManager size must be 0x68");
} // namespace moho
