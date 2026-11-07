#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Engine addition, dedicated server (plan WP3.6, WP3.7): a player's commands on their way into the sim.
//
// A player names things by their view's ids (remote/ViewIdMap.h), and the bytes are theirs, so a command
// doesn't reach its seat as sent: it's decoded, its ids go back to the sim's (remote/InboundIds.h), and
// what the seat gets is marshalled here. One that doesn't decode, or names an id the view was never
// given, stops here. Each command gets one answer, in the order sent: the beat it went in, or why not.
//
// The network's thread only queues them. An id map is written by that view's work, so they're taken on
// the sim's thread once the last beat's views are over, at most one beat later than they could have gone
// in. A player can't spend more of the sim's time than `kMaxCommandsPerBeat` and `kMaxBytesPerBeat` allow:
// the rest waits its turn.

namespace moho
{
  class RRuleGameRules;
}

namespace faf::remote
{
  class CServerClient;
  class CViewIdMap;
} // namespace faf::remote

namespace faf::server
{
  class CSeatIntake
  {
  public:
    static constexpr std::size_t kMaxCommandsPerBeat = 64u;
    static constexpr std::size_t kMaxBytesPerBeat = 64u * 1024u;
    /** Waiting past this, a player sends faster than any game of theirs could. */
    static constexpr std::size_t kMaxWaiting = 4096u;

    /** The id map of an army's view; null: none yet, or no such view. */
    using MapOfArmy = std::function<const remote::CViewIdMap*(std::int32_t army)>;
    /** Whether an army's client holds a record with this id; see remote/InboundIds.h. */
    using ViewHolds = std::function<bool(std::int32_t army, std::uint32_t id)>;
    /** A reliable message for a player. */
    using Answer = std::function<void(std::int32_t uid, std::vector<std::uint8_t> message)>;

    CSeatIntake();
    ~CSeatIntake();
    CSeatIntake(const CSeatIntake&) = delete;
    CSeatIntake& operator=(const CSeatIntake&) = delete;

    /** Before any command can arrive. */
    void AddSeat(std::int32_t uid, remote::CServerClient& seat);
    /** The army whose view this player has; without one, only ids that are never renumbered go through. */
    void SetArmy(std::int32_t uid, std::int32_t army);

    /** From any thread: one command as the sim's stream has it (type, size, payload). False: too many waiting. */
    [[nodiscard]] bool Push(std::int32_t uid, const std::uint8_t* command, std::size_t size);

    /** The player's out of the game: what they left waiting goes with them. */
    void Forget(std::int32_t uid);

    /** On the sim's thread, with no view's work going on. `rules`, for blueprint ids: the same each time. */
    void Drain(moho::RRuleGameRules* rules, const MapOfArmy& maps, const ViewHolds& holds, const Answer& answer);

    [[nodiscard]] std::uint64_t Applied() const noexcept { return mApplied; }
    [[nodiscard]] std::uint64_t Refused() const noexcept { return mRefused; }
    [[nodiscard]] std::uint64_t Dropped() const noexcept { return mDropped; }
    /** Ids that came in a view's numbers and went on in the sim's. */
    [[nodiscard]] std::uint64_t IdsTranslated() const noexcept;
    /** A line for the console; call once the sim has stopped. */
    [[nodiscard]] std::string Report() const;

  private:
    struct SSeat
    {
      remote::CServerClient* seat = nullptr;
      std::int32_t army = -1;
      std::deque<std::vector<std::uint8_t>> waiting;
    };
    struct STaken
    {
      std::int32_t uid;
      SSeat* seat;
      std::vector<std::uint8_t> command;
    };
    struct SDecoding;

    std::mutex mLock;
    std::map<std::int32_t, SSeat> mSeats;
    std::atomic<std::size_t> mWaiting{0};
    std::vector<STaken> mTaking;
    std::unique_ptr<SDecoding> mDecoding; // made on the sim's thread, when the first command comes
    std::uint64_t mApplied = 0;
    std::uint64_t mRefused = 0;
    std::uint64_t mDropped = 0;
  };
} // namespace faf::server
