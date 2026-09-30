#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "Wm3Quaternion.h"

namespace moho
{
  struct REntityBlueprint;
  struct SSTICommandIssueData;

  struct SSTICommandConstantData
  {
    static gpg::RType* sType;

    int32_t cmd;
    /**
     * Formation-script selector, `-1` when the order carries no formation.
     * `CUnitCommand::CUnitCommand` (0x006E82AE) copies it in as a plain dword
     * from the issue payload, `CUnitCommand::SetFormation` (0x006E8?) resets it
     * to `0xFFFFFFFF`, and `CUnitCommand::Move` (0x006E88F5) tests
     * `cmp dword ptr [ebp+48h], 0FFFFFFFFh / jle` before handing it to
     * `CAiFormationDBImpl::GetScriptName(scriptIndex, unitSet)`. It was typed
     * `void*` here, which forced its readers to go looking for an int lane in
     * the variable-data payload instead.
     */
    int32_t mFormationScriptIndex;
    Wm3::Quatf origin;
    float unk1;
    REntityBlueprint* blueprint;
    msvc8::string unk2;

    /**
     * Address: 0x00554630 (FUN_00554630, Moho::SSTICommandConstantData::MemberDeserialize)
     *
     * What it does:
     * Loads one command-constant payload lane from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005546C0 (FUN_005546C0, Moho::SSTICommandConstantData::MemberSerialize)
     *
     * What it does:
     * Stores one command-constant payload lane to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  static_assert(offsetof(SSTICommandConstantData, cmd) == 0x00, "SSTICommandConstantData::cmd offset must be 0x00");
  static_assert(offsetof(SSTICommandConstantData, mFormationScriptIndex) == 0x04, "SSTICommandConstantData::mFormationScriptIndex offset must be 0x04");
  static_assert(
    offsetof(SSTICommandConstantData, origin) == 0x08, "SSTICommandConstantData::origin offset must be 0x08"
  );
  static_assert(offsetof(SSTICommandConstantData, unk1) == 0x18, "SSTICommandConstantData::unk1 offset must be 0x18");
  static_assert(
    offsetof(SSTICommandConstantData, blueprint) == 0x1C, "SSTICommandConstantData::blueprint offset must be 0x1C"
  );
  static_assert(
    offsetof(SSTICommandConstantData, unk2) == 0x20, "SSTICommandConstantData::unk2 offset must be 0x20"
  );
  static_assert(sizeof(SSTICommandConstantData) == 0x3C, "SSTICommandConstantData size must be 0x3C");
  /**
   * Address: 0x00552630 (FUN_00552630, preregister_SSTICommandConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTICommandConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTICommandConstantDataTypeInfo();

  /**
   * Address: 0x005527C0 (FUN_005527C0, struct_CommandIssueDataHelper::struct_CommandIssueDataHelper)
   *
   * What it does:
   * Initializes one published-command descriptor (`destination`) from issue-data
   * lanes (command id, orientation/aux scalars, blueprint, and Lua-object lexical
   * payload) and returns `destination`. Defined in CUnitCommand.cpp; declared here
   * so the client-side `ISSUE_Command` keystone (Sim.cpp) can publish a command.
   */
  SSTICommandConstantData* InitializePublishedCommandDescriptorFromIssueData(
    SSTICommandConstantData* destination,
    const SSTICommandIssueData* issueData
  );
} // namespace moho
