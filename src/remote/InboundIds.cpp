#include "remote/InboundIds.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/command/SSTITarget.h"

// Engine addition, server mode: see InboundIds.h.

namespace faf::remote
{
  void CCommandIdRewriter::Drop(const char* const message, const char* const kind, const std::uint32_t id)
  {
    ++mDropped;
    char text[160];
    std::snprintf(text, sizeof(text), "%s: unknown %s id 0x%08x", message, kind, id);
    mLastDrop = text;
    gpg::Warnf("command ids: dropped %s", text);
  }

  bool CCommandIdRewriter::Entity(const char* const message, std::uint32_t& id)
  {
    const std::uint32_t before = id;
    if (!RewriteEntity(id)) {
      Drop(message, "entity", before);
      return false;
    }
    mIdsRewritten += id != before ? 1u : 0u;
    return true;
  }

  bool CCommandIdRewriter::Command(const char* const message, std::uint32_t& id)
  {
    const std::uint32_t before = id;
    if (!RewriteCommand(id)) {
      Drop(message, "command", before);
      return false;
    }
    mIdsRewritten += id != before ? 1u : 0u;
    return true;
  }

  bool CCommandIdRewriter::Target(const char* const message, moho::SSTITarget& target)
  {
    if (target.mType != moho::EAiTargetType::AITARGET_Entity) {
      return true;
    }
    std::uint32_t id = target.mEntityId;
    if (!Entity(message, id)) {
      return false;
    }
    target.mEntityId = id;
    return true;
  }

  bool CCommandIdRewriter::Entities(const char* const message, const EntitySet& in, EntitySet& out)
  {
    bool known = true;
    in.ForEachValue([&](const unsigned int value) {
      std::uint32_t id = value;
      if (known && Entity(message, id)) {
        (void)out.Add(static_cast<moho::EntId>(id));
      } else {
        known = false;
      }
    });
    return known;
  }

  bool CCommandIdRewriter::IssueData(const char* const message, moho::SSTICommandIssueData& data)
  {
    if (data.unk04 != -1) {
      auto partner = static_cast<std::uint32_t>(data.unk04);
      if (!Command(message, partner)) {
        return false;
      }
      data.unk04 = static_cast<std::int32_t>(partner);
    }
    if ((static_cast<std::uint32_t>(data.mIndex) & 0xFF000000u) != 0xFF000000u) {
      auto before = static_cast<std::uint32_t>(data.mIndex);
      if (!Command(message, before)) {
        return false;
      }
      data.mIndex = static_cast<std::int32_t>(before);
    }
    return Target(message, data.mTarget) && Target(message, data.mTarget2);
  }

  void CCommandIdRewriter::CountBlipTarget(const moho::SSTICommandIssueData& data) noexcept
  {
    const auto index = static_cast<std::size_t>(data.mCommandType);
    if (data.mTarget.mType == moho::EAiTargetType::AITARGET_Entity && (data.mTarget.mEntityId >> 28u) == 3u
        && index < mBlipTargets.size()) {
      ++mBlipTargets[index];
    }
  }

  std::uint32_t TranslateSelectionMask(
    const CViewIdMap& map, const moho::SSyncFilterMaskBlock& in, moho::SSyncFilterMaskBlock& out,
    const std::function<bool(std::uint32_t simId)>& known
  )
  {
    std::uint32_t leftOut = 0;
    out = moho::SSyncFilterMaskBlock{};
    in.ForEachValue([&](const unsigned int value) {
      std::uint32_t simId = 0;
      if (map.EntityToSim(value, simId) && known(simId)) {
        (void)out.Add(simId);
      } else {
        ++leftOut;
      }
    });
    return leftOut;
  }

  void CCommandIdRewriter::SetCommandSource(const moho::CommandSourceId sourceId)
  {
    mNext.SetCommandSource(sourceId);
  }

  void CCommandIdRewriter::OnCommandSourceTerminated()
  {
    mNext.OnCommandSourceTerminated();
  }

  void CCommandIdRewriter::VerifyChecksum(const gpg::MD5Digest& digest, const moho::CSeqNo seqNo)
  {
    mNext.VerifyChecksum(digest, seqNo);
  }

  void CCommandIdRewriter::RequestPause()
  {
    mNext.RequestPause();
  }

  void CCommandIdRewriter::Resume()
  {
    mNext.Resume();
  }

  void CCommandIdRewriter::SingleStep()
  {
    mNext.SingleStep();
  }

  void CCommandIdRewriter::CreateUnit(
    const uint32_t armyIndex, const moho::RResId& id, const moho::SCoordsVec2& pos, const float heading
  )
  {
    ++mCommands;
    mNext.CreateUnit(armyIndex, id, pos, heading);
  }

  void CCommandIdRewriter::CreateProp(const char* const id, const Wm3::Vec3f& loc)
  {
    ++mCommands;
    mNext.CreateProp(id, loc);
  }

  void CCommandIdRewriter::DestroyEntity(const moho::EntId entityId)
  {
    ++mCommands;
    auto id = static_cast<std::uint32_t>(entityId);
    if (Entity("DestroyEntity", id)) {
      mNext.DestroyEntity(static_cast<moho::EntId>(id));
    }
  }

  void CCommandIdRewriter::WarpEntity(const moho::EntId entityId, const moho::VTransform& transform)
  {
    ++mCommands;
    auto id = static_cast<std::uint32_t>(entityId);
    if (Entity("WarpEntity", id)) {
      mNext.WarpEntity(static_cast<moho::EntId>(id), transform);
    }
  }

  void CCommandIdRewriter::ProcessInfoPair(const moho::EntId entityId, const gpg::StrArg key, const gpg::StrArg value)
  {
    ++mCommands;
    auto id = static_cast<std::uint32_t>(entityId);
    if (Entity("ProcessInfoPair", id)) {
      mNext.ProcessInfoPair(static_cast<moho::EntId>(id), key, value);
    }
  }

  void CCommandIdRewriter::IssueCommand(
    const EntitySet& entities, const moho::SSTICommandIssueData& data, const bool clear
  )
  {
    ++mCommands;
    EntitySet units{};
    moho::SSTICommandIssueData translated(data);
    if (Entities("IssueCommand", entities, units) && IssueData("IssueCommand", translated)) {
      CountBlipTarget(translated);
      mNext.IssueCommand(units, translated, clear);
    }
  }

  void CCommandIdRewriter::IssueFactoryCommand(
    const EntitySet& entities, const moho::SSTICommandIssueData& data, const bool clear
  )
  {
    ++mCommands;
    EntitySet units{};
    moho::SSTICommandIssueData translated(data);
    if (Entities("IssueFactoryCommand", entities, units) && IssueData("IssueFactoryCommand", translated)) {
      CountBlipTarget(translated);
      mNext.IssueFactoryCommand(units, translated, clear);
    }
  }

  void CCommandIdRewriter::IncreaseCommandCount(const moho::CmdId id, const int count)
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    if (Command("IncreaseCommandCount", command)) {
      mNext.IncreaseCommandCount(static_cast<moho::CmdId>(command), count);
    }
  }

  void CCommandIdRewriter::DecreaseCommandCount(const moho::CmdId id, const int count)
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    if (Command("DecreaseCommandCount", command)) {
      mNext.DecreaseCommandCount(static_cast<moho::CmdId>(command), count);
    }
  }

  void CCommandIdRewriter::SetCommandTarget(const moho::CmdId id, const moho::SSTITarget& target)
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    moho::SSTITarget translated = target;
    if (Command("SetCommandTarget", command) && Target("SetCommandTarget", translated)) {
      mNext.SetCommandTarget(static_cast<moho::CmdId>(command), translated);
    }
  }

  void CCommandIdRewriter::SetCommandType(const moho::CmdId id, const moho::EUnitCommandType type)
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    if (Command("SetCommandType", command)) {
      mNext.SetCommandType(static_cast<moho::CmdId>(command), type);
    }
  }

  void CCommandIdRewriter::SetCommandCells(
    const moho::CmdId id, const gpg::core::FastVector<moho::SOCellPos>& cells, const Wm3::Vector3<float>& target
  )
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    if (Command("SetCommandCells", command)) {
      mNext.SetCommandCells(static_cast<moho::CmdId>(command), cells, target);
    }
  }

  void CCommandIdRewriter::RemoveCommandFromUnitQueue(const moho::CmdId id, const moho::EntId unitId)
  {
    ++mCommands;
    auto command = static_cast<std::uint32_t>(id);
    auto unit = static_cast<std::uint32_t>(unitId);
    if (Command("RemoveCommandFromUnitQueue", command) && Entity("RemoveCommandFromUnitQueue", unit)) {
      mNext.RemoveCommandFromUnitQueue(static_cast<moho::CmdId>(command), static_cast<moho::EntId>(unit));
    }
  }

  void CCommandIdRewriter::ExecuteLuaInSim(const char* const lua, const LuaPlus::LuaObject& args)
  {
    ++mCommands;
    mNext.ExecuteLuaInSim(lua, args);
  }

  void CCommandIdRewriter::LuaSimCallback(
    const char* const name, const LuaPlus::LuaObject& args, const EntitySet& entities
  )
  {
    ++mCommands;
    EntitySet units{};
    if (Entities("LuaSimCallback", entities, units) && CallbackIds(name, args)) {
      mNext.LuaSimCallback(name, args, units);
    }
  }

  bool CCommandIdRewriter::CallbackIds(const char* const name, const LuaPlus::LuaObject& args)
  {
    if (name == nullptr || !args.IsTable()) {
      return true;
    }
    for (const SCallbackIdField& field : kCallbackIdFields) {
      if (std::strcmp(field.callback, name) != 0) {
        continue;
      }
      const LuaPlus::LuaObject value = args[field.key];
      if (!value.IsString()) {
        continue;
      }
      const char* const text = value.GetString();
      const std::size_t length = text != nullptr ? std::strlen(text) : 0u;
      if (length == 0u || length > 10u || std::strspn(text, "0123456789") != length) {
        continue;
      }
      const unsigned long long parsed = std::strtoull(text, nullptr, 10);
      if (parsed > 0xFFFFFFFFull) {
        continue;
      }
      auto id = static_cast<std::uint32_t>(parsed);
      const std::uint32_t before = id;
      if (!Entity("LuaSimCallback", id)) {
        return false;
      }
      if (id != before) {
        // The payload is this command's own, decoded from the client's message: rewritten in place.
        char rewritten[16];
        std::snprintf(rewritten, sizeof(rewritten), "%u", id);
        const_cast<LuaPlus::LuaObject&>(args).SetString(field.key, rewritten);
      }
    }
    return true;
  }

  void CCommandIdRewriter::ExecuteDebugCommand(
    const char* const command, const Wm3::Vector3<float>& position, const uint32_t army, const EntitySet& entities
  )
  {
    ++mCommands;
    EntitySet units{};
    if (Entities("ExecuteDebugCommand", entities, units)) {
      mNext.ExecuteDebugCommand(command, position, army, units);
    }
  }

  void CCommandIdRewriter::AdvanceBeat(const int beats)
  {
    mNext.AdvanceBeat(beats);
  }

  void CCommandIdRewriter::EndGame()
  {
    mNext.EndGame();
  }
} // namespace faf::remote
