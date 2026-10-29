#pragma once

#include <cstdint>
#include <vector>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

// Engine addition (plan WP2.7): the launch-info half of `CLobby::LaunchGame` (0x007C38C0),
// factored out so the lobby and a game server build a session's launch info, army order,
// command sources and seed with one piece of code. Who the participants are, and how each is
// given a client index and a command source, is the caller's (`ILaunchParticipants`): the
// lobby answers with its peers exactly as before, a server with its match roster.

namespace LuaPlus
{
  class LuaObject;
  class LuaState;
}

namespace moho
{
  class LaunchInfoNew;
  struct SSTICommandSource;

  /** The bookkeeping `CLobby::AssignClientIndex` and `CLobby::AssignCommandSource` do on peers. */
  class ILaunchParticipants
  {
  public:
    virtual ~ILaunchParticipants() = default;

    [[nodiscard]] virtual std::int32_t LocalUid() const = 0;

    /**
     * Called once, just before the first player is assigned: where the lobby's original
     * `LaunchGame` began the part that cleans up its peers when it throws.
     */
    virtual void BeginAssignments() {}

    /**
     * Gives `ownerId` the next client index the first time it is named (`localIndex` for the
     * local participant); `name` is the config's name for one not known yet.
     */
    virtual void AssignClientIndex(std::int32_t& clientIndex, std::int32_t ownerId, const char* name, std::int32_t& localIndex) = 0;

    /** `ownerId`'s command source, appending one to `commandSources` the first time. */
    virtual std::uint32_t AssignCommandSource(
      std::int32_t timeouts, std::int32_t ownerId, msvc8::vector<SSTICommandSource>& commandSources,
      std::uint32_t& localSource
    ) = 0;
  };

  struct SLaunchBuild
  {
    /** Non-null: the launch failed before anything was assigned; the `LaunchFailed` reason. */
    const char* failure = nullptr;
    boost::shared_ptr<LaunchInfoNew> launchInfo;
    msvc8::string mapName;
    std::int32_t clientCount = 0;        // client indices handed out
    std::int32_t localClientIndex = -1;
    std::uint32_t localSourceId = 0xFFu;
  };

  /**
   * Builds a session's launch info from a lobby game config (`CLobby.LaunchGame(gameConfig)`'s
   * table) as `CLobby::LaunchGame` does: scenario info with the options, army order by slot,
   * civilian armies, client indices and command sources in the order players then observers
   * are named, seed and cheats. `state` is the user Lua state. Throws `std::runtime_error`
   * when the local participant is not in the launch or there are too many participants (and
   * whatever a malformed entry throws), possibly after some assignments were made.
   */
  [[nodiscard]] SLaunchBuild BuildLaunchInfo(
    const LuaPlus::LuaObject& gameConfig, ILaunchParticipants& participants, std::int32_t seed, bool isMultiplayer,
    LuaPlus::LuaState* state
  );

  /** One participant of a roster. */
  struct SLaunchClient
  {
    std::int32_t uid = 0;
    msvc8::string name;                  // the command source takes this name
    std::int32_t clientIndex = -1;       // -1: not assigned
    std::uint32_t commandSource = 0xFFu; // 0xFF: none
  };

  /**
   * Participants from a list (a game server's match roster, a test): the same rules as the
   * lobby's peers, a participant the config names that the list lacks being added at the end.
   */
  class CLaunchRoster final : public ILaunchParticipants
  {
  public:
    CLaunchRoster(std::int32_t localUid, msvc8::string localName, std::vector<SLaunchClient> remotes);

    [[nodiscard]] std::int32_t LocalUid() const override { return mLocalUid; }
    void AssignClientIndex(std::int32_t& clientIndex, std::int32_t ownerId, const char* name, std::int32_t& localIndex)
      override;
    std::uint32_t AssignCommandSource(
      std::int32_t timeouts, std::int32_t ownerId, msvc8::vector<SSTICommandSource>& commandSources,
      std::uint32_t& localSource
    ) override;

    [[nodiscard]] const std::vector<SLaunchClient>& Remotes() const noexcept { return mRemotes; }

  private:
    [[nodiscard]] SLaunchClient* Find(std::int32_t uid) noexcept;

    std::int32_t mLocalUid;
    msvc8::string mLocalName;
    std::vector<SLaunchClient> mRemotes;
  };
} // namespace moho
