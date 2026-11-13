#pragma once

#include <cstdint>
#include <span>
#include <vector>

#include "remote/wire/CommandLane.h"

namespace moho
{
  struct REntityBlueprint;
  struct SSTICommandConstantData;
  struct SSTICommandVariableData;
  struct SSyncData;
} // namespace moho

// Engine addition, server mode (plan WP5.14): a server-mode client's end of the command-records lane
// (remote/wire/CommandLane.h). Each view's lane becomes its beat packet's four command lists, as a lockstep client's
// sim fills them (`CCommandDB::PublishSyncData`): `CWldSession::DoBeat` then makes, updates and deletes the
// `UserCommandIssueHelper`s from them as in lockstep (descriptors before the units' updates resolve their queues, the
// packets after), and `UserUnit:GetCommandQueue()` and every other user-side reader find the records. An update or a
// removal of a command this client wasn't sent is dropped and counted (`CCommandLaneReceiver`), never handed to the
// session, whose `ApplyBeatCommandPackets` would dereference the helper it can't find.

namespace faf::remote::client
{
  /** `SSTICommandVariableData` from the lane's record. */
  void CommandDataToSim(const wire::SCommandData& data, moho::SSTICommandVariableData& out);
  /** `SSTICommandConstantData` from the lane's descriptor; `blueprints` by the content tables' ordinal. */
  void CommandDescriptorToSim(
    const wire::SCommandDescriptor& descriptor,
    const std::vector<const moho::REntityBlueprint*>& blueprints,
    moho::SSTICommandConstantData& out
  );

  class CCommandLaneApplier
  {
  public:
    /** `blueprints`: the client's own, by the content tables' ordinal (`ResolveBlueprints`). */
    explicit CCommandLaneApplier(std::vector<const moho::REntityBlueprint*> blueprints);

    /** One view's lane into `packet`'s command lists. False when it doesn't decode (nothing applied, counted). */
    bool Apply(std::span<const std::uint8_t> lane, moho::SSyncData& packet);

    [[nodiscard]] const wire::SCommandLaneCounts& Counts() const noexcept
    {
      return mReceiver.Counts();
    }
    /** Descriptors naming a blueprint this client's rules don't have (the helper gets none). */
    [[nodiscard]] std::uint64_t UnknownBlueprints() const noexcept
    {
      return mUnknownBlueprints;
    }
    [[nodiscard]] const wire::CCommandLaneReceiver& Receiver() const noexcept
    {
      return mReceiver;
    }

  private:
    std::vector<const moho::REntityBlueprint*> mBlueprints;
    wire::CCommandLaneReceiver mReceiver;
    wire::CCommandLaneReceiver::SBeat mBeat;
    std::uint64_t mUnknownBlueprints = 0;
  };
} // namespace faf::remote::client
