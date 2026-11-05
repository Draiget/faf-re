#include "server/SeatIntake.h"

#include <cstring>
#include <utility>

#include "gpg/core/streams/Stream.h"
#include "legacy/containers/AutoPtr.h"
#include "lua/LuaObject.h"
#include "moho/misc/CDecoder.h"
#include "moho/net/CMessage.h"
#include "moho/net/ECmdStreamOp.h"
#include "remote/InboundIds.h"
#include "remote/ServerClient.h"
#include "remote/ViewIdMap.h"
#include "remote/client/RemoteClientManager.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

namespace faf::server
{
  namespace
  {
    // A stream message: type, 2 bytes of whole size, payload (moho/net/CMessage.h).
    constexpr std::size_t kCommandHeaderBytes = 3;

    [[nodiscard]] bool NamesIds(const moho::ECmdStreamOp op) noexcept
    {
      return op != moho::ECmdStreamOp::CMDST_RequestPause && op != moho::ECmdStreamOp::CMDST_Resume;
    }
  } // namespace

  /** Decoder, translator and marshaller in a row: what comes out of the last goes on the seat being served. */
  struct CSeatIntake::SDecoding
  {
    explicit SDecoding(moho::RRuleGameRules* const rules)
      : lua(new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE))
      , capture(
          [this](moho::CMessage& message) {
            answer = seat->ReceiveCommand(message, &beat) ? remote::net::ECommandAnswer::Applied : remote::net::ECommandAnswer::Refused;
          },
          nullptr
        )
      , marshaller(std::make_unique<moho::CMarshaller>(&capture))
      , translator(*marshaller, noMap)
      , decoder(std::make_unique<moho::CDecoder>(&translator, noRecording, rules, lua.get()))
    {
      translator.SetHeldTest([this](const std::uint32_t id) { return (*holds)(army, id); });
    }

    std::unique_ptr<LuaPlus::LuaState> lua; // the decoder's own, apart from the sim's
    fa::auto_ptr<gpg::Stream> noRecording;
    remote::client::CRemoteClientManager capture;
    std::unique_ptr<moho::CMarshaller> marshaller;
    remote::CViewIdMap noMap{-1};
    remote::CInboundIdTranslator translator;
    std::unique_ptr<moho::CDecoder> decoder;
    remote::CServerClient* seat = nullptr;
    std::int32_t army = -1;
    const ViewHolds* holds = nullptr;
    remote::net::ECommandAnswer answer = remote::net::ECommandAnswer::Dropped;
    std::int32_t beat = 0;
  };

  CSeatIntake::CSeatIntake() = default;
  CSeatIntake::~CSeatIntake() = default;

  void CSeatIntake::AddSeat(const std::int32_t uid, remote::CServerClient& seat)
  {
    const std::scoped_lock lock(mLock);
    mSeats[uid].seat = &seat;
  }

  void CSeatIntake::SetArmy(const std::int32_t uid, const std::int32_t army)
  {
    const std::scoped_lock lock(mLock);
    const auto found = mSeats.find(uid);
    if (found != mSeats.end()) {
      found->second.army = army;
    }
  }

  bool CSeatIntake::Push(const std::int32_t uid, const std::uint8_t* const command, const std::size_t size)
  {
    const std::scoped_lock lock(mLock);
    const auto found = mSeats.find(uid);
    if (found == mSeats.end() || found->second.waiting.size() >= kMaxWaiting) {
      return false;
    }
    found->second.waiting.emplace_back(command, command + size);
    mWaiting.fetch_add(1u, std::memory_order_relaxed);
    return true;
  }

  void CSeatIntake::Forget(const std::int32_t uid)
  {
    const std::scoped_lock lock(mLock);
    const auto found = mSeats.find(uid);
    if (found != mSeats.end()) {
      mWaiting.fetch_sub(found->second.waiting.size(), std::memory_order_relaxed);
      found->second.waiting.clear();
    }
  }

  void CSeatIntake::Drain(moho::RRuleGameRules* const rules, const MapOfArmy& maps, const ViewHolds& holds, const Answer& answer)
  {
    if (mWaiting.load(std::memory_order_relaxed) == 0u) {
      return;
    }
    mTaking.clear();
    {
      const std::scoped_lock lock(mLock);
      for (auto& [uid, seat] : mSeats) {
        std::size_t count = 0;
        std::size_t bytes = 0;
        // The first always goes: a command may be as big as the limit.
        while (!seat.waiting.empty() && count < kMaxCommandsPerBeat && (count == 0u || bytes + seat.waiting.front().size() <= kMaxBytesPerBeat)) {
          bytes += seat.waiting.front().size();
          ++count;
          mTaking.push_back(STaken{uid, &seat, std::move(seat.waiting.front())});
          seat.waiting.pop_front();
        }
        mWaiting.fetch_sub(count, std::memory_order_relaxed);
      }
    }
    if (mDecoding == nullptr) {
      mDecoding = std::make_unique<SDecoding>(rules);
    }

    for (STaken& taken : mTaking) {
      moho::CMessage message(moho::MessageType(taken.command[0]), taken.command.size() - kCommandHeaderBytes);
      if (taken.command.size() > kCommandHeaderBytes) {
        std::memcpy(message.mBuff.start_ + kCommandHeaderBytes, taken.command.data() + kCommandHeaderBytes, taken.command.size() - kCommandHeaderBytes);
      }

      SDecoding& decoding = *mDecoding;
      decoding.seat = taken.seat->seat;
      decoding.answer = remote::net::ECommandAnswer::Dropped;
      decoding.beat = 0;
      const auto op = static_cast<moho::ECmdStreamOp>(taken.command[0]);
      if (taken.command[0] >= remote::CServerClient::kOpCount || !remote::SeatMaySend(op) || !NamesIds(op)) {
        // Whether it's allowed is the seat's to say, and these have nothing to translate.
        decoding.answer = taken.seat->seat->ReceiveCommand(message, &decoding.beat) ? remote::net::ECommandAnswer::Applied : remote::net::ECommandAnswer::Refused;
      } else {
        const remote::CViewIdMap* const map = maps(taken.seat->army);
        decoding.translator.SetMap(map != nullptr ? *map : decoding.noMap);
        decoding.army = taken.seat->army;
        decoding.holds = &holds;
        decoding.decoder->ReceiveMessage(&message, nullptr);
      }

      switch (decoding.answer) {
      case remote::net::ECommandAnswer::Applied:
        ++mApplied;
        break;
      case remote::net::ECommandAnswer::Refused:
        ++mRefused;
        break;
      case remote::net::ECommandAnswer::Dropped:
        ++mDropped;
        break;
      }

      std::vector<std::uint8_t> reply;
      remote::net::ByteWriter writer(reply);
      writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::CommandAnswer));
      writer.Varint(static_cast<std::uint64_t>(decoding.beat));
      writer.Byte(static_cast<std::uint8_t>(decoding.answer));
      answer(taken.uid, std::move(reply));
    }
    mTaking.clear();
  }

  std::uint64_t CSeatIntake::IdsTranslated() const noexcept
  {
    return mDecoding != nullptr ? mDecoding->translator.IdsRewritten() : 0u;
  }

  std::string CSeatIntake::Report() const
  {
    std::string line = std::to_string(mApplied) + " commands from players, " + std::to_string(IdsTranslated()) + " ids translated, " + std::to_string(mRefused) +
      " refused, " + std::to_string(mDropped) + " dropped";
    if (mDecoding != nullptr && !mDecoding->translator.LastDrop().empty()) {
      line += " (last unknown id: " + mDecoding->translator.LastDrop() + ")";
    }
    return line;
  }
} // namespace faf::server
