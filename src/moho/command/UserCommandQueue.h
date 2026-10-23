#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "legacy/containers/Deque.h"
#include "moho/command/CmdDefs.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class UserUnit;
  struct UserCommandIssueHelper;

  /**
   * What one pending queue edit does when the queue replays it over the
   * acknowledged links (`RebuildAndGetUserUnitManagerQueue`, 0x008B6F60): the
   * switch on the entry's +0x04 at 0x008B7092.
   */
  enum class EUserQueueEdit : std::int32_t
  {
    Add = 0,    // UserUnitManagerAdd (0x008B6DE0)
    Reset = 1,  // ResetUserUnitManagerState (0x008B6E60)
    Remove = 2, // RecordUnitManagerCommandHelperRemoval (0x008B6EE0)
  };

  /**
   * One edit the UI made to a unit's command queue ahead of the sim. Until the
   * sim's sequence reaches `mCommandId` (`AdvanceUserCommandManagerBySeq`,
   * 0x008B7350: `mov ecx,[eax]` then `sub ecx,esi`) the edit is replayed over
   * the acknowledged links, which is what puts a command in the queue the
   * moment it is issued.
   */
  struct UserManagerHelperEntry
  {
    /**
     * Address: 0x008B6B80 (FUN_008B6B80 -- this constructor emitted out of
     * line, `this` in EAX and the edit in EDX; zero callers, every use is
     * inlined into the three queue edits.)
     */
    UserManagerHelperEntry(
      const CmdId commandId, const EUserQueueEdit edit, UserCommandIssueHelper* const helper, const CmdId index
    ) noexcept
      : mCommandId(commandId)
      , mEdit(edit)
      , mHelper(helper)
      , mIndex(index)
    {}

    CmdId mCommandId;                // +0x00 the command this edit belongs to
    EUserQueueEdit mEdit;            // +0x04
    UserCommandIssueHelper* mHelper; // +0x08 the command added or removed; null for Reset
    CmdId mIndex;                    // +0x0C Add: the issue data's `mIndex`; a 0xFF source byte appends mHelper
  };
  static_assert(sizeof(UserManagerHelperEntry) == 0x10, "UserManagerHelperEntry size must be 0x10");
  static_assert(offsetof(UserManagerHelperEntry, mEdit) == 0x04, "UserManagerHelperEntry::mEdit offset must be 0x04");
  static_assert(offsetof(UserManagerHelperEntry, mHelper) == 0x08, "UserManagerHelperEntry::mHelper offset must be 0x08");
  static_assert(offsetof(UserManagerHelperEntry, mIndex) == 0x0C, "UserManagerHelperEntry::mIndex offset must be 0x0C");

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
   * Each link is a weak reference to the command's issue helper, so a command
   * the session retires leaves a null link behind rather than a dangling
   * pointer. `primaryLinks` holds what the sim acknowledged; while edits are
   * pending, `resolvedLinks` is that run with the edits replayed over it.
   *
   * The destructor is the implicit one (0x008B6BE0): `resolvedLinks`, the
   * edit ring (`_Tidy` 0x008B7B50), then `primaryLinks`, each run's links
   * unlinked (0x008B79A0) and its heap block freed. `delete queue` compiles to
   * the scalar deleting destructor 0x008C5D00 (flags folded to 1, `this` in
   * EAX; zero callers, the two `delete`s in `~UserUnit` are inlined), and
   * 0x008C5AF0 is VC8's `auto_ptr<UserCommandQueue>::reset` (`if (p != ptr)
   * delete ptr; ptr = p;`), zero callers.
   */
  class UserCommandQueue
  {
  public:
    /**
     * Address: 0x008BF612 (inside FUN_008BF420, once per queue)
     *
     * What it does:
     * Stores the owner and lets the members arm themselves: both link runs on
     * their inline pairs, the edit ring empty, the resolved run clean. The
     * words at +0x04 and +0x3C are not written.
     */
    explicit UserCommandQueue(UserUnit* owner);

    UserUnit* ownerUnit;                                                  // +0x00
    std::uint32_t mUnknown04;                                             // +0x04
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2> primaryLinks;  // +0x08
    msvc8::deque<UserManagerHelperEntry> issueQueue;                      // +0x28
    std::uint32_t mUnknown3C;                                             // +0x3C
    gpg::fastvector_n<WeakPtr<UserCommandIssueHelper>, 2> resolvedLinks; // +0x40
    std::uint8_t resolvedLinksDirty;                                      // +0x60
    std::uint8_t pad_0061_0068[0x07];
  };
  static_assert(offsetof(UserCommandQueue, primaryLinks) == 0x08, "UserCommandQueue::primaryLinks offset must be 0x08");
  static_assert(offsetof(UserCommandQueue, issueQueue) == 0x28, "UserCommandQueue::issueQueue offset must be 0x28");
  static_assert(offsetof(UserCommandQueue, resolvedLinks) == 0x40, "UserCommandQueue::resolvedLinks offset must be 0x40");
  static_assert(
    offsetof(UserCommandQueue, resolvedLinksDirty) == 0x60, "UserCommandQueue::resolvedLinksDirty offset must be 0x60"
  );
  static_assert(sizeof(UserCommandQueue) == 0x68, "UserCommandQueue size must be 0x68");
} // namespace moho
