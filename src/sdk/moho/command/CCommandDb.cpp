#include "moho/command/CCommandDb.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <sstream>
#include <utility>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/sim/SimDriver.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] std::uint32_t ResolveCommandUnitEntryAddressForDump(const moho::CScriptObject* const entry) noexcept
  {
    if (entry == nullptr) {
      return 0u;
    }

    if (!moho::SCommandUnitSet::IsUsableEntry(entry)) {
      return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entry));
    }

    const moho::Unit* const unit = moho::SCommandUnitSet::UnitFromEntry(entry);
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(unit));
  }

  void WriteCommandEntryDump(
    std::ostringstream& stream, const moho::CmdId key, const moho::CUnitCommand* const command
  )
  {
    stream << gpg::STR_Printf("  0x%08x =>", static_cast<std::uint32_t>(key)).c_str();

    if (command == nullptr) {
      stream << " NULL\n";
      return;
    }

    stream << "\n";
    stream << gpg::STR_Printf("    GetType() => %d\n", static_cast<int>(command->mVarDat.mCmdType)).c_str();

    const auto& entries = command->mUnitSet.mVec;
    const int unitCount = static_cast<int>(entries.size());
    const char* unitSuffix = "s";
    if (unitCount != 0) {
      unitSuffix = (unitCount == 1) ? ":" : "s:";
    }
    stream << gpg::STR_Printf("    %d Unit%s\n", unitCount, unitSuffix).c_str();

    for (const moho::CScriptObject* const entry : entries) {
      stream << gpg::STR_Printf("      0x%08x\n", ResolveCommandUnitEntryAddressForDump(entry)).c_str();
    }
  }

  /**
   * Address: 0x006E0A70 (FUN_006E0A70, ??1CommandDatabase@Moho@@QAE@@Z -- the
   * diagnostic-dump half of the destructor, ahead of the member-teardown tail
   * cited on `msvc8::detail::rb_tree::~rb_tree` in RbTree.h)
   *
   * What it does:
   * Dies with a dump of every still-owned command when the command map is
   * destroyed non-empty.
   */
  void ValidateCommandMapEmptyOrDie(const msvc8::map<moho::CmdId, moho::CUnitCommand*>& commands)
  {
    if (commands.empty()) {
      return;
    }

    std::ostringstream message{};
    message << "Trying to destroy the sim's command database, but it isn't empty.\n\n";

    for (const auto& entry : commands) {
      WriteCommandEntryDump(message, entry.first, entry.second);
    }

    gpg::Die("%s", message.str().c_str());
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006E09C0 (FUN_006E09C0, ??0CommandDatabase@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one command database with its owning Sim and empty
   * container/id-pool lanes.
   *
   * Sentinel allocation (0x006E2840, FUN_006E2840, sub_6E2840):
   * The binary buys the command map's header/sentinel node through a raw
   * node allocator (isNil=0 by default), then this constructor's own body
   * patches isNil=1 and self-links left/parent/right before zeroing
   * `_Mysize` - the same split-allocator shape as
   * `AllocateAllUnitsTreeNode`/`InitializeAllUnitsTreeHeadLane` in
   * EntityDb.cpp. Here the split is fused inside `commands`'s own default
   * construction: `msvc8::map`'s shared `detail::rb_tree` default
   * constructor (legacy/containers/RbTree.h) calls `rb_tree::buy_head()`,
   * which performs the identical alloc + self-link + isNil=1/color=black
   * sequence, so no separate call is needed in this constructor's body.
   *
   * `pendingReleasedCmdIds` (binary's `this->vec`):
   * Declared at +0x0CC0, immediately after `pool`'s 0x0CB0-byte `IdPool`
   * span, closing the struct out exactly at the asserted 0xCD0 size.
   * `msvc8::vector<CmdId>`'s default constructor already zeroes
   * `_Myfirst`/`_Mylast`/`_Myend`, matching the binary's explicit
   * zero-stores.
   */
  CCommandDb::CCommandDb(Sim* const sim)
    : sim(sim)
    , commands()
    , pool()
    , pendingReleasedCmdIds()
  {
  }

  /**
   * Address: 0x006E0A70 (FUN_006E0A70, ??1CommandDatabase@Moho@@QAE@@Z)
   * Mangled: ??1CommandDatabase@Moho@@QAE@@Z
   *
   * What it does:
   * Validates that the command map is empty (dumping and terminating if not),
   * then releases id-pool recycle lanes. `pendingReleasedCmdIds` and
   * `commands` need no explicit teardown here: the binary's own tail --
   * `erase(begin, end)` on the command map followed by `operator delete` on
   * its header and zeroed head/size lanes -- is exactly the member
   * destruction the compiler emits automatically for `commands` at the close
   * of this scope (see the FUN_006E0A70 citation on
   * `msvc8::detail::rb_tree::~rb_tree`, RbTree.h); there is no separate
   * hand-written call for it in this function's own body.
   */
  CCommandDb::~CCommandDb()
  {
    ValidateCommandMapEmptyOrDie(commands);

    pool.mSubRes2.Reset();
    pool.mReleasedLows.mWords.ResetStorageToInline();
  }

  /**
   * Address: 0x006E0DB0 (FUN_006E0DB0, Moho::CommandDatabase::AddIssueData)
   *
   * What it does:
   * Resolves a fresh command id when the incoming id is unresolved, constructs
   * one command from issue-data lanes, inserts it into the command map, and
   * returns the command pointer.
   */
  CUnitCommand* CCommandDb::AddIssueData(SSTICommandIssueData issueData)
  {
    CmdId commandId = issueData.nextCommandId;

    if ((static_cast<std::uint32_t>(commandId) & 0xFF000000u) == 0xFF000000u) {
      unsigned int nextLowId = 0u;
      if (pool.mReleasedLows.mWords.Empty()) {
        nextLowId = static_cast<unsigned int>(pool.mNextLowId);
        pool.mNextLowId = static_cast<std::int32_t>(nextLowId + 1u);
      } else {
        nextLowId = pool.mReleasedLows.GetNext(std::numeric_limits<unsigned int>::max());
        (void)pool.mReleasedLows.Remove(nextLowId);
      }

      commandId = static_cast<CmdId>(nextLowId | 0x80000000u);
      issueData.nextCommandId = commandId;
    }

    CUnitCommand* const command = new (std::nothrow) CUnitCommand(sim, issueData, commandId);
    if (command == nullptr) {
      return nullptr;
    }

    /**
     * Address: 0x006E15B0 (FUN_006E15B0, `msvc8::map<Moho::CmdId,
     * Moho::CUnitCommand*>::insert_unique` -- `Moho::CCommandDb::commands` in
     * CCommandDb.h. Matches `rb_tree::insert_unique` field for field: descend
     * recording the last branch taken, `where == leftmost()` fast path
     * straight to `insert_at`, otherwise the predecessor check via
     * `rb_decrement`, then link or return the colliding node with `false`.
     * Reached from here and from `MemberDeserialize` (FUN_006E1430) below.)
     */
    commands.insert(msvc8::map<CmdId, CUnitCommand*>::value_type(command->mConstDat.cmd, command));
    return command;
  }

  /**
   * Address: 0x006E0F50 (FUN_006E0F50)
   *
   * What it does:
   * Publishes per-command sync event lanes into one outgoing sync packet,
   * swaps pending released command-id vectors with packet storage, and updates
   * id-pool recycle state.
   */
  void CCommandDb::PublishSyncData(SSyncData* const syncData, const bool forceRefresh)
  {
    for (const auto& entry : commands) {
      CUnitCommand* const command = entry.second;
      if (command != nullptr) {
        command->RefreshPublishedCommandEvent(forceRefresh, syncData);
      }
    }

    std::swap(pendingReleasedCmdIds, syncData->mPendingReleasedCommandIds);
    pool.Update();
  }

  /**
   * Address: 0x006E2E10 (FUN_006E2E10)
   *
   * What it does:
   * Runs one `CCommandDb` destructor lane and then releases the object storage
   * with scalar `operator delete`, returning the same pointer.
   */
  [[maybe_unused]] CCommandDb* ReleaseCommandDbInstance(CCommandDb* const db)
  {
    db->~CCommandDb();
    ::operator delete(db);
    return db;
  }

  /**
   * Address: 0x006E13A0 (FUN_006E13A0, Moho::CCommandDB::MemberSerialize)
   *
   * What it does:
   * Serializes each stored command pointer as `OWNED`, then writes the
   * terminating null command-pointer lane.
   */
  void CCommandDb::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    for (const auto& entry : commands) {
      gpg::RRef commandRef{};
      (void)gpg::RRef_CUnitCommand(&commandRef, entry.second);
      gpg::WriteRawPointer(archive, commandRef, gpg::TrackedPointerState::Owned, NullOwnerRef());
    }

    gpg::RRef nullRef{};
    (void)gpg::RRef_CUnitCommand_P(&nullRef, nullptr);
    gpg::WriteRawPointer(archive, nullRef, gpg::TrackedPointerState::Owned, NullOwnerRef());
  }

  /**
   * Address: 0x006E1430 (FUN_006E1430, Moho::CCommandDB::MemberDeserialize)
   *
   * What it does:
   * Reads owned command pointers until null terminator, assigns command ids
   * from the id-pool lanes, and inserts commands into the runtime map.
   *
   * The binary does not clear `commands` before repopulating it here (that
   * would be `erase_range`'s emission, FUN_006E22D0, which this function
   * never calls) -- deserialization only ever runs against a freshly
   * constructed, still-empty command database.
   */
  void CCommandDb::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    CUnitCommand* command = nullptr;
    gpg::RRef ownerRef{};
    (void)archive->ReadPointerOwned_CUnitCommand(&command, &ownerRef);

    while (command != nullptr) {
      BVIntSet& releasedLowIds = pool.mReleasedLows;
      std::uint32_t nextLowId = 0u;

      if (releasedLowIds.mWords.Empty()) {
        nextLowId = static_cast<std::uint32_t>(pool.mNextLowId);
        pool.mNextLowId = static_cast<std::int32_t>(nextLowId + 1u);
      } else {
        nextLowId = releasedLowIds.GetNext(std::numeric_limits<unsigned int>::max());

        const unsigned int wordIndex = (nextLowId >> 5u) - releasedLowIds.mFirstWordIndex;
        const std::size_t wordCount = releasedLowIds.mWords.Size();
        if (static_cast<std::size_t>(wordIndex) < wordCount) {
          releasedLowIds.mWords[wordIndex] &= ~(1u << (nextLowId & 0x1Fu));
          releasedLowIds.Finalize();
        }
      }

      const CmdId commandId = static_cast<CmdId>(nextLowId | 0x80000000u);
      command->mConstDat.cmd = commandId;
      commands.insert(msvc8::map<CmdId, CUnitCommand*>::value_type(commandId, command));

      ownerRef.mObj = nullptr;
      ownerRef.mType = nullptr;
      command = nullptr;
      (void)archive->ReadPointerOwned_CUnitCommand(&command, &ownerRef);
    }
  }

  /**
   * Address: 0x006E3300 (FUN_006E3300)
   *
   * What it does:
   * Register-shape adapter that forwards one command-db save lane to
   * `CCommandDb::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCommandDbMemberLanePrimary(
    gpg::WriteArchive* const archive,
    CCommandDb* const commandDb
  )
  {
    commandDb->MemberSerialize(archive);
  }

  /**
   * Address: 0x006E3CF0 (FUN_006E3CF0)
   *
   * What it does:
   * Register-shape adapter that forwards one command-db load lane to
   * `CCommandDb::MemberDeserialize`.
   */
  [[maybe_unused]] void DeserializeCommandDbMemberLane(
    CCommandDb* const commandDb,
    gpg::ReadArchive* const archive
  )
  {
    commandDb->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006E3D00 (FUN_006E3D00)
   *
   * What it does:
   * Secondary register-shape adapter that forwards one command-db save lane to
   * `CCommandDb::MemberSerialize`.
   */
  [[maybe_unused]] void SerializeCommandDbMemberLaneSecondary(
    gpg::WriteArchive* const archive,
    CCommandDb* const commandDb
  )
  {
    commandDb->MemberSerialize(archive);
  }
} // namespace moho
